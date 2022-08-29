# SPDX-License-Identifier: MIT

from m1n1.trace.i2c import *

I2CTracer = I2CTracer._reloadcls()

seen_regs = set()

def read_cstring(vaddr):
    phys = p.hv_translate(vaddr, False, False)
    if phys == 0:
        return "~~bad addr~~"
    return p.iface.readmem(phys, 256).split(b"\x00")[0].decode("ascii")

def hook_write_reg(ctx):
    r = hv.ctx.regs
    seen_regs.add((read_cstring(r[3]), r[4]))
    hv.log(f"DRIVER: {read_cstring(r[1])}: write {r[2]:x}/{r[4]:04x}({read_cstring(r[3])})"
            f" <- {r[6]:2x}({read_cstring(r[5])})")
    return True

def hook_read_reg(ctx):
    r = hv.ctx.regs
    seen_regs.add((read_cstring(r[3]), r[4]))
    hv.log(f"DRIVER: {read_cstring(r[1])}: read {r[2]:x}/{r[4]:04x}({read_cstring(r[3])})")
    return True

def hook_wmask_reg(ctx):
    r = hv.ctx.regs
    seen_regs.add((read_cstring(r[3]), r[4]))
    hv.log(f"DRIVER: {read_cstring(r[1])}: wmask {r[2]:x}/{r[4]:04x}({read_cstring(r[3])}),"
            f" {r[6]:02x}({read_cstring(r[5])}) <- {r[8]:02x}({read_cstring(r[7])})")
    return True

driver_base = hv.resolve_symbol("com.apple.driver.AppleCS42L84Audio:__TEXT_EXEC")

#readReg = base + 0xd81c - 0x8000
maskWriteReg = driver_base + 0xd9d4 - 0x8000
verifyRegBit = driver_base + 0xe3b8 - 0x8000

hv.clear_hw_bps()
hv.add_hw_bp(driver_base + 0xd81c - 0x8000, hook=hook_read_reg)
hv.add_hw_bp(driver_base + 0xd8f0 - 0x8000, hook=hook_write_reg)

##hv.add_hw_bp(writeReg, lambda ctx: hv.log("DRIVER WRITE: %s(%x), %s"))
hv.add_hw_bp(maskWriteReg, hook=hook_wmask_reg)
#hv.add_hw_bp(verifyRegBit)

class CS42L84Tracer(I2CDevTracer):
    def stop(self):
        I2CDevTracer.stop(self)
        #raise Exception("")

i2c_tracer = I2CTracer(hv, f"/arm-io/i2c2", verbose=0)
i2c_tracer.add_device(0x4b, CS42L84Tracer())
i2c_tracer.start()
