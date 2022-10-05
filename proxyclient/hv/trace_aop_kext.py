# SPDX-License-Identifier: MIT
import re
from construct import *

def decode_logprint(hv):
    u = hv.u
    p = u.proxy
    iface = u.iface
    regs = hv.ctx.regs

    string = hv.readmem(regs[1], 1024).split(b"\x00")[0].decode("ascii")
    stack = hv.readmem(hv.ctx.sp[0] + 48, 512)
    def va_arg(t):
        nonlocal stack
        d, stack = stack[:8], stack[8:]
        return t.parse(d)

    utypes = {
        "hh": Int8ul,
        "h": Int16ul,
        None: Int32ul,
        "l": Int64ul,
        "ll": Int64ul,
        "q": Int64ul,
        "s": Int64ul,
        "t": Int64ul,
        "z": Int64ul,
    }

    stypes = {
        "hh": Int8sl,
        "h": Int16sl,
        None: Int32sl,
        "l": Int64sl,
        "ll": Int64sl,
        "q": Int64sl,
        "s": Int64sl,
        "t": Int64sl,
    }

    #print(string)

    def format_arg(match):
        pat, flags, width, mod, conv = match.group(0, 1, 2, 3, 4)
        if conv == "%":
            return "%"
        elif conv == "s":
            pointed = hv.readmem(va_arg(Int64ul), 1024).split(b"\x00")[0]
            try:
                return pointed.decode("ascii")
            except ValueError:
                return "<non-ascii: %s>" % pointed
        elif conv in "di":
            v = va_arg(stypes[mod])
            return f"%{flags or ''}{width or ''}{conv or ''}" % v
        elif conv in "ouxX":
            v = va_arg(utypes[mod])
            return f"%{flags or ''}{width or ''}{conv or ''}" % v
        elif conv in "p":
            return f"0x{va_arg(Int64ul):x}"
        elif conv == "c":
            return f"{va_arg(Int8ul):c}"  
        else:
            return f"[{pat!r}:{va_arg(Int64ul):x}]"

    string = re.sub('%([-#0 +]*)([1-9][0-9]*)?(hh|h|l|ll|q|L|j|z|Z|t)?([diouxXeEfFgGaAcsCSpnm%])',
                    format_arg, string)
    print(f"[{regs[0]:d}] {string}", end="")

    return True

hv.add_kext_symbols("proxyclient/hv/kernel.macho_kexts/AppleAOPAudio.kext")
hv.add_kext_symbols("proxyclient/hv/kernel.macho_kexts/AppleSPU.kext")
hv.clear_hw_bps()
hv.add_sym_bp("com.apple.driver.AppleAOPAudio:__ZN16AppleAOPAudioLog4VLogEjPKcPc",
              hook=lambda ctx: decode_logprint(hv))

