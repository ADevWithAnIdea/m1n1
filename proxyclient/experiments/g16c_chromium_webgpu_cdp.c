#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Only an owned local browser and local test page. CDP uses NUL frames over
 * inherited pipes, never a network debugging endpoint. */
static int input_fd,output_fd,loaded;
static pid_t browser;
static char frame[4*1024*1024];
static double deadline;
static double now(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))exit(2);return t.tv_sec+t.tv_nsec*1e-9;}
static void cleanup(void){if(browser>0){kill(-browser,SIGTERM);for(int i=0;i<20;i++){if(waitpid(browser,NULL,WNOHANG)==browser){browser=0;return;}usleep(25000);}kill(-browser,SIGKILL);waitpid(browser,NULL,0);browser=0;}}
static void fail(const char *s){fprintf(stderr,"WEBGPU_CDP_ERROR=%s errno=%d\n",s,errno);cleanup();exit(2);}
static void send_json(const char *s){size_t n=strlen(s)+1;while(n){ssize_t w=write(input_fd,s,n);if(w<=0)fail("pipe write");s+=w;n-=(size_t)w;}}
static char *read_frame(void){size_t n=0;while(n<sizeof(frame)-1){int ms=(int)((deadline-now())*1000);if(ms<=0)fail("owned browser deadline");struct pollfd p={.fd=output_fd,.events=POLLIN};int r=poll(&p,1,ms);if(r<0&&errno==EINTR)continue;if(r<=0)fail("CDP poll");char c;ssize_t got=read(output_fd,&c,1);if(got<0&&errno==EINTR)continue;if(got!=1)fail("CDP EOF");if(!c){frame[n]=0;return frame;}frame[n++]=c;}fail("CDP frame too large");return NULL;}
static int top_id(const char *s){int depth=0;for(size_t i=0;s[i];i++){if(s[i]=='{'||s[i]=='['){depth++;continue;}if(s[i]=='}'||s[i]==']'){depth--;continue;}if(s[i]=='"'){size_t start=++i;while(s[i]&&(s[i]!='"'||(i>start&&s[i-1]=='\\'))){if(s[i]=='\\'&&s[i+1])i++;i++;}if(!s[i])return -1;if(depth==1&&i-start==2&&s[start]=='i'&&s[start+1]=='d'){const char *p=s+i+1;while(*p==' '||*p=='\t')p++;if(*p++!=':')continue;return atoi(p);}}}return -1;}
static char *response(int id){for(;;){char *s=read_frame();if(strstr(s,"\"Page.loadEventFired\""))loaded=1;if(top_id(s)==id)return s;}}
static void field(const char *s,const char *name,char *out,size_t cap){char pattern[80];if(snprintf(pattern,sizeof(pattern),"\"%s\"",name)>=(int)sizeof(pattern))fail("field name");const char *p=strstr(s,pattern);if(!p)fail(name);p+=strlen(pattern);while(*p==' ')p++;if(*p++!=':')fail("field colon");while(*p==' ')p++;if(*p++!='"')fail("field string");size_t n=0;while(*p&&*p!='"'){if(*p=='\\'||n+1>=cap)fail("unexpected identifier");out[n++]=*p++;}if(*p!='"')fail("unterminated identifier");out[n]=0;}
int main(void){
 signal(SIGPIPE,SIG_IGN);int to[2],from[2];if(pipe(to)||pipe(from))fail("pipe");deadline=now()+70;
 browser=fork();if(browser<0)fail("fork");if(!browser){
  if(setpgid(0,0))_exit(120);
  int r=fcntl(to[0],F_DUPFD,10),w=fcntl(from[1],F_DUPFD,10);if(r<0||w<0)_exit(121);
  close(to[0]);close(to[1]);close(from[0]);close(from[1]);if(dup2(r,3)<0||dup2(w,4)<0)_exit(122);close(r);close(w);
  int log=open("/tmp/chromium-webgpu-browser.log",O_WRONLY|O_CREAT|O_TRUNC,0600);if(log<0)_exit(123);dup2(log,1);dup2(log,2);if(log>4)close(log);
  execl("/opt/chromium/chromium","chromium","--headless=new","--ozone-platform=headless","--enable-gpu","--use-gl=angle","--use-angle=vulkan","--enable-unsafe-webgpu","--enable-webgpu-developer-features","--enable-features=Vulkan","--disable-software-rasterizer","--ignore-gpu-blocklist","--no-sandbox","--no-first-run","--no-default-browser-check","--disable-background-networking","--disable-component-update","--disable-sync","--user-data-dir=/tmp/chromium-webgpu-profile-v1","--remote-debugging-pipe","--enable-logging=stderr","--log-level=0","about:blank",(char *)NULL);_exit(124);
 }
 setpgid(browser,browser);close(to[0]);close(from[1]);input_fd=to[1];output_fd=from[0];
 send_json("{\"id\":1,\"method\":\"Target.createTarget\",\"params\":{\"url\":\"about:blank\"}}");char target[128],session[128],msg[4096];field(response(1),"targetId",target,sizeof(target));
 snprintf(msg,sizeof(msg),"{\"id\":2,\"method\":\"Target.attachToTarget\",\"params\":{\"targetId\":\"%s\",\"flatten\":true}}",target);send_json(msg);field(response(2),"sessionId",session,sizeof(session));
 snprintf(msg,sizeof(msg),"{\"id\":3,\"method\":\"Page.enable\",\"sessionId\":\"%s\"}",session);send_json(msg);response(3);
 loaded=0;snprintf(msg,sizeof(msg),"{\"id\":4,\"method\":\"Page.navigate\",\"params\":{\"url\":\"file:///opt/chromium/webgpu.html\"},\"sessionId\":\"%s\"}",session);send_json(msg);response(4);
 while(!loaded){char *s=read_frame();if(strstr(s,"\"Page.loadEventFired\""))loaded=1;}
 snprintf(msg,sizeof(msg),"{\"id\":5,\"method\":\"Runtime.evaluate\",\"params\":{\"expression\":\"globalThis.gpuWorkloadDone || Promise.resolve({status:'FAIL',error:'Missing workload promise'})\",\"awaitPromise\":true,\"returnByValue\":true},\"sessionId\":\"%s\"}",session);send_json(msg);char *answer=response(5);printf("WEBGPU_CDP_RESULT=%s\n",answer);fflush(stdout);
 send_json("{\"id\":6,\"method\":\"Browser.close\"}");cleanup();return 0;
}
