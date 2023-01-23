#include "utils.h"
#include "exception.h"
#include "hv.h"
#include "smp.h"
#include "string.h"

#define MAX_NCHANNELS 32
#define REG_TX_REPORT_READ 0x10100
#define REG_RX_REPORT_READ 0x14100

static u64 periph_base;
static u32 report_npieces[MAX_NCHANNELS];

static void emit_mmiotrace(u64 pc, u64 addr, u64 *data, u64 width, u64 flags, bool sync)
{
    struct hv_evt_mmiotrace evt = {
        .flags = flags | FIELD_PREP(MMIO_EVT_CPU, smp_id()),
        .pc = pc,
        .addr = addr,
    };

    if (width > 3)
        evt.flags |= FIELD_PREP(MMIO_EVT_WIDTH, 3) | MMIO_EVT_MULTI;
    else
        evt.flags |= FIELD_PREP(MMIO_EVT_WIDTH, width);

    for (int i = 0; i < (1 << width); i += 8) {
        evt.data = *data++;
        hv_wdt_suspend();
        uartproxy_send_event(EVT_MMIOTRACE, &evt, sizeof(evt));
        if (sync) {
            iodev_flush(uartproxy_iodev);
        }
        hv_wdt_resume();
        evt.addr += 8;
    }
}

static bool admac_is_report_read(u64 addr, int *channo)
{
    u64 offset = addr - periph_base;

    if (offset >= REG_TX_REPORT_READ \
            && offset < REG_TX_REPORT_READ + (MAX_NCHANNELS/2)*4) {
        *channo = (offset - REG_TX_REPORT_READ)/4*2;
        return true;
    }

    if (offset >= REG_RX_REPORT_READ \
            && offset < REG_RX_REPORT_READ + (MAX_NCHANNELS/2)*4) {
        *channo = (offset - REG_RX_REPORT_READ)/4*2 + 1;
        return true;
    }

    return false;
}

static bool admac_hook(struct exc_info *ctx, u64 addr, u64 *val, bool write, int width) {
    int channo;

    if (write) {
    	if (!hv_pa_write(ctx, addr, val, width))
			return false;
    } else {
    	if (!hv_pa_read(ctx, addr, val, width))
			return false;
    }

    if (admac_is_report_read(addr, &channo)) {
        report_npieces[channo]++;
        if (report_npieces[channo] % 4 != 0)
            goto async;

        struct hv_vm_proxy_hook_data hook = {
            .flags = FIELD_PREP(MMIO_EVT_WIDTH, width),
            .id = 0,
            .addr = addr,
            .data = {0},
        };
        memcpy(hook.data, val, 1 << width);
        hv_exc_proxy(ctx, START_HV, HV_HOOK_VM, &hook);
        return true;
    }
async:
    if (write)
        emit_mmiotrace(ctx->elr, addr, val, width, MMIO_EVT_WRITE, false);
    else
        emit_mmiotrace(ctx->elr, addr, val, width, 0, false);

    return true;
}

void hv_map_admac_tracer(u64 base)
{
	periph_base = base;
	for (int i = 0; i < MAX_NCHANNELS; i++)
		report_npieces[i] = 0;
    hv_map_hook(base, admac_hook, 0x34000);
}
