/* SPDX-License-Identifier: MIT */

#include "hv.h"
#include "aic.h"
#include "iodev.h"
#include "string.h"
#include "uart.h"
#include "uart_regs.h"
#include "usb.h"

bool active = false;

u32 ucon = 0;
u32 utrstat = 0;
u32 ufstat = 0;

int vuart_irq = 0;

#define VUART_RX_BUFFER_SIZE 4096
#define VUART_LOG_LINE_SIZE  1024

static bool vuart_single_channel;
static u8 vuart_rx_buffer[VUART_RX_BUFFER_SIZE];
static size_t vuart_rx_read;
static size_t vuart_rx_write;
static size_t vuart_rx_count;
static u8 vuart_prompt_buffer[VUART_RX_BUFFER_SIZE];
static size_t vuart_prompt_count;

static void update_irq(void)
{
    ssize_t rx_queued = vuart_rx_count;

    if (!vuart_single_channel) {
        iodev_handle_events(IODEV_USB_VUART);
        rx_queued += iodev_can_read(IODEV_USB_VUART);
    }

    utrstat |= UTRSTAT_TXBE | UTRSTAT_TXE;
    utrstat &= ~UTRSTAT_RXD;

    if (rx_queued) {
        utrstat |= UTRSTAT_RXD;
        if (rx_queued > 15)
            ufstat = FIELD_PREP(UFSTAT_RXCNT, 15) | UFSTAT_RXFULL;
        else
            ufstat = FIELD_PREP(UFSTAT_RXCNT, rx_queued);

        if (FIELD_GET(UCON_RXMODE, ucon) == UCON_MODE_IRQ && ucon & UCON_RXTO_ENA) {
            utrstat |= UTRSTAT_RXTO;
        }
    } else {
        ufstat = 0;
    }

    if (FIELD_GET(UCON_TXMODE, ucon) == UCON_MODE_IRQ && ucon & UCON_TXTHRESH_ENA) {
        utrstat |= UTRSTAT_TXTHRESH;
    }

    if (vuart_irq) {
        uart_clear_irqs();
        if (utrstat & (UTRSTAT_TXTHRESH | UTRSTAT_RXTHRESH | UTRSTAT_RXTO)) {
            aic_set_sw(vuart_irq, true);
        } else {
            aic_set_sw(vuart_irq, false);
        }
    }

    //     printf("HV: vuart UTRSTAT=0x%x UFSTAT=0x%x UCON=0x%x\n", utrstat, ufstat, ucon);
}

static void handle_vuart_passthrough(uint8_t b)
{
    const char PREFIX[] = "HVLOG: ";
    static int state = 0;

    if (!PREFIX[state]) {
        if (b == '\r' || b == '\n') {
            printf("\n");
            state = 0;
            return;
        }
        printf("%c", b);
        return;
    }

    if (b == PREFIX[state])
        state++;
    else
        state = 0;

    if (!PREFIX[state])
        printf("%s", PREFIX);
}

static bool handle_vuart_output(uint8_t b)
{
    static char line[VUART_LOG_LINE_SIZE];
    static size_t pos;

    if (!vuart_single_channel) {
        handle_vuart_passthrough(b);
        return false;
    }

    if (pos < sizeof(line) - 1)
        line[pos++] = b;
    line[pos] = '\0';

    /*
     * G17P bring-up: keep a single-user launch command outside XNU's input
     * FIFO until bash is actually ready. Preloading the ordinary RX ring is
     * unreliable because the kernel consumes it during serial-console boot.
     * Releasing here is entirely target-side and does not stop guest CPUs.
     */
    if (vuart_prompt_count && strstr(line, "-sh-3.2# ")) {
        size_t pending = vuart_prompt_count;
        size_t released = hv_vuart_inject(vuart_prompt_buffer, pending);
        if (released == pending) {
            vuart_prompt_count = 0;
            printf("G17P VUART prompt release: %lu bytes\n", released);
            update_irq();
        }
    }

    if (b != '\n' && pos < sizeof(line) - 1)
        return false;

    printf("VUART> %s", line);
    if (b != '\n')
        printf("\n");
#ifdef HV_VUART_MARKER_TRIGGER
    /*
     * G17P capture: the partial-render client emits this one-shot marker only
     * after its untraced prefix has completed.  Stopping on every READY line
     * is both too early for a later-command capture and needlessly invasive.
     */
    bool marker = strstr(line, "G17P_PARTIAL_ARM_CAPTURE") != NULL;
#else
    bool marker = false;
#endif
    pos = 0;
    return marker;
}

ssize_t hv_vuart_inject(const void *buf, size_t length)
{
    const u8 *bytes = buf;
    size_t written = 0;

    while (written < length && vuart_rx_count < sizeof(vuart_rx_buffer)) {
        vuart_rx_buffer[vuart_rx_write] = bytes[written++];
        vuart_rx_write = (vuart_rx_write + 1) % sizeof(vuart_rx_buffer);
        vuart_rx_count++;
    }

    return written;
}

ssize_t hv_vuart_inject_at_prompt(const void *buf, size_t length)
{
    size_t stored = length < sizeof(vuart_prompt_buffer)
                        ? length
                        : sizeof(vuart_prompt_buffer);

    memcpy(vuart_prompt_buffer, buf, stored);
    vuart_prompt_count = stored;
    return stored;
}

static bool handle_vuart(struct exc_info *ctx, u64 addr, u64 *val, bool write, int width)
{
    UNUSED(ctx);
    UNUSED(width);

    addr &= 0xfff;

    update_irq();

    if (write) {
        //         printf("HV: vuart W 0x%lx <- 0x%lx (%d)\n", addr, *val, width);
        switch (addr) {
            case UCON:
                ucon = *val;
                break;
            case UTXH: {
                uint8_t b = *val;
                if (iodev_can_write(IODEV_USB_VUART))
                    iodev_write(IODEV_USB_VUART, &b, 1);
                if (handle_vuart_output(b))
                    hv_exc_proxy(ctx, START_HV, HV_VUART_MARKER, NULL);
                break;
            }
            case UTRSTAT:
                utrstat &= ~(*val & (UTRSTAT_TXTHRESH | UTRSTAT_RXTHRESH | UTRSTAT_RXTO));
                break;
        }
    } else {
        switch (addr) {
            case UCON:
                *val = ucon;
                break;
            case URXH:
                if (vuart_rx_count) {
                    *val = vuart_rx_buffer[vuart_rx_read];
                    vuart_rx_read = (vuart_rx_read + 1) % sizeof(vuart_rx_buffer);
                    vuart_rx_count--;
                } else if (iodev_can_read(IODEV_USB_VUART)) {
                    uint8_t c;
                    iodev_read(IODEV_USB_VUART, &c, 1);
                    *val = c;
                } else {
                    *val = 0;
                }
                break;
            case UTRSTAT:
                *val = utrstat;
                break;
            case UFSTAT:
                *val = ufstat;
                break;
            default:
                *val = 0;
                break;
        }
        //         printf("HV: vuart R 0x%lx -> 0x%lx (%d)\n", addr, *val, width);
    }

    return true;
}

void hv_vuart_poll(void)
{
    if (!active)
        return;

    update_irq();
}

void hv_map_vuart(u64 base, int irq, iodev_id_t iodev)
{
    hv_map_hook(base, handle_vuart, 0x1000);
    vuart_single_channel = iodev < IODEV_USB0 || iodev >= IODEV_USB0 + USB_IODEV_COUNT;
    if (!vuart_single_channel)
        usb_iodev_vuart_setup(iodev);
    vuart_irq = irq;
    active = true;
    printf("HV: VUART using %s console transport\n",
           vuart_single_channel ? "proxy-queued" : "secondary USB");
}
