#include <stdint.h>
#include <stdio.h>
static void emit(uint32_t iterations,unsigned jobs) {
 uint32_t out[40]; for(unsigned i=0;i<40;i++)out[i]=0xa5a5a5a5u;
 for(unsigned lane=0;lane<16;lane++) {
  uint32_t value=0x5a110000u^lane;
  for(uint32_t j=0;j<iterations;j++)value=(value<<7|value>>25)+0x9e3779b9u+j;
  out[lane]=value;
 }
 for(unsigned job=0;job<jobs;job++)out[16+job]=0x5a220000u|job;
 for(unsigned i=0;i<40;i++)for(unsigned byte=0;byte<4;byte++)printf("%02x",(out[i]>>(byte*8))&255u);
 puts("");
}
int main(void){emit(1,1);emit(1000000,1);emit(4000000,8);return 0;}
