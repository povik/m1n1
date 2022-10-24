# SPDX-License-Identifier: MIT
import time
import struct
from enum import IntEnum
from construct import Container

from ..utils import *

class R_ROUTINE_CTL(Register32):
    LOADED = 7, 0

class R_PC_LIMITS(Register32):
    TOP = 31, 16
    BOT = 15, 0

class LEAPCoreRegs(RegMap):
    STATE0 = irange(0x00_000, 4096, 0x8), Register32
    STATE1 = irange(0x10_000, 3072, 0x8), Register32
    STATE2 = irange(0x20_000, 3072, 0x8), Register32
    STATE3 = irange(0x30_000, 3072, 0x8), Register32

    INST0 = irange(0x40_000, 0x4_000, 0x4), Register32
    INST1 = irange(0x50_000, 0x4_000, 0x4), Register32
    INST2 = irange(0x60_000, 0x4_000, 0x4), Register32
    INST3 = irange(0x70_000, 0x4_000, 0x4), Register32

    ROUTINE_CTL = 0x80_008, R_ROUTINE_CTL
    GLOBAL_EN   = 0x80_00c, Register32
    UNK_0c      = 0x80_01c, Register32
    COUNTER     = 0x80_044, Register32

    ON_CYCLES_SUM = 0x80_048, Register32
    ON_CYCLES     = irange(0x80_04c, 8, 0x4), Register32
    FLAGS         = irange(0x80_06c, 8, 0x4), Register32
    PC            = irange(0x80_08c, 8, 0x4), Register32
    PC_LIMITS     = irange(0x80_0ac, 8, 0x4), R_PC_LIMITS
    ROUT_UNK1     = irange(0x80_0cc, 8, 0x4), Register32
    ROUT_UNK2     = irange(0x80_0ec, 8, 0x4), Register32
    ROUT_UNK3     = irange(0x80_10c, 8, 0x4), Register32 # r/o
    ROUT_UNK4     = irange(0x80_12c, 8, 0x4), Register32 # if there's non-zero, ^^ does counting
    ROUT_UNK5     = irange(0x80_14c, 8, 0x4), Register32
    PTR_UNK1      = irange(0x80_16c, 8, 0x4), Register32

class LEAPClusterRegs(RegMap):
    WAITEMPTY_SIEVE = (irange(0xe00000, 4, 0x400), irange(0x0, 8, 0x4), irange(0x0, 4, 0x40)), Register32
    WAITFULL_SIEVE  = (irange(0xe00020, 4, 0x400), irange(0x0, 8, 0x4), irange(0x0, 4, 0x40)), Register32

class LEAP:
    def __init__(self, parent, regs, no):
        self.u = parent.u
        self.parent = parent
        self.no = no
        self.regs = regs
        self.scratch = parent.scratch

    @classmethod
    def _assemble(cls, f):
        for line in f:
            bits = []

            for term in line.split():
                if term.endswith(":"):
                    continue
                if term.endswith(","):
                    term = term[:-1]
                bits.append(int(term, 16))

            yield tuple((bits + [0, 0, 0, 0])[:4])

    def load_program(self, fname):
        r = self.regs
        regions = [r.INST0, r.INST1, r.INST2, r.INST3]

        with open(fname, "r") as f:
            for i, parts in enumerate(self._assemble(f)):
                for r, v in zip(regions, parts):
                    r[i].val = v

    def dump_program(self, fname="/dev/stdout"):
        r = self.regs
        regions = [r.INST0, r.INST1, r.INST2, r.INST3]

        with open(fname, "w") as f:
            for i in range(0x200):
                inst, bot, mid, top = [r[i].val for r in regions]
                print(f"{i:4x}: {inst:8x},\t{bot:x},\t{mid:x},\t{top:x}")

    def enable(self):
        r = self.regs
        r.GLOBAL_EN.val = 0x3

    def reset(self):
        r = self.regs
        r.ROUTINE_CTL.val = 0x00_00_ff_00
        r.ROUTINE_CTL.val = 0x00_00_00_00

    def disable(self):
        r = self.regs
        r.GLOBAL_EN.val = 0x0

    def single_step(self, pos, ridx=0):
        r = self.regs
        r.PC_LIMITS[ridx].val = (pos + 1)*0x1_0000 | pos
        r.ROUTINE_CTL.val = 0x00_00_01_00 << ridx
        r.ROUTINE_CTL.val = 0x00_01_00_00 << ridx
        r.ROUTINE_CTL.val = 0x00_01_00_01 << ridx

    def zeroout(self):
        r = self.regs
        for i in range(0x800):
            r.STATE0[i].val = 0
            r.STATE1[i].val = 0
            r.STATE2[i].val = 0
            r.STATE3[i].val = 0

    def read_bank(self, bank, length=None):
        if not length:
            length = len(bank.range.ranges[0])
        self.u.proxy.memcpy32(self.scratch, bank[0].addr,
                              length * 8)
        return struct.unpack(
            f"<{length * 2}I",
            self.u.iface.readmem(self.scratch, length * 8)
        )[::2]

    def save_context(self, crop=None):
        r = self.regs
        if crop is None:
            crop = 0x800

        return Container(
            s0=self.read_bank(r.STATE0, crop),
            s1=self.read_bank(r.STATE1, crop),
            s2=self.read_bank(r.STATE2, crop),
            s3=self.read_bank(r.STATE3, crop),
        )

    def write_bank(self, bank, vals, base=0):
        stride = bank.range.ranges[0].step // 4
        vals_padded = [0] * (len(vals) * stride)
        vals_padded[::stride] = vals
        self.u.iface.writemem(self.scratch, struct.pack(
            f"<{len(vals) * stride}I",
            *vals_padded
        ))
        self.u.proxy.memcpy32(bank[base].addr, self.scratch,
                              len(vals) * 4 * stride)

    def load_context(self, ctx):
        r = self.regs
        self.write_bank(r.STATE0, ctx.bank0)
        self.write_bank(r.STATE1, ctx.bank1)
        self.write_bank(r.STATE2, ctx.bank2)
        self.write_bank(r.STATE3, ctx.bank3)

    def run_once(self, ridx):
        r = self.regs
        r.ROUTINE_CTL.val &= ~(0x1 << ridx)
        r.ROUTINE_CTL.val |= (0x100 << ridx)
        r.ROUTINE_CTL.val &= ~(0x100 << ridx)
        r.ROUTINE_CTL.val |= (0x10000 << ridx)
        r.ROUTINE_CTL.val |= (0x1 << ridx)

    def estimate_routine_rate(self, routidx):
        span = self.regs.PC_LIMITS[routidx].reg
        length = span.TOP - span.BOT
        val1 = self.regs.ON_CYCLES[routidx].val
        time.sleep(1.0)
        val2 = self.regs.ON_CYCLES[routidx].val
        return (val2 - val1) / length

class LEAPCluster:
    def __init__(self, u, base, ncores=4):
        self.u = u
        self.scratch = u.malloc(0x400)
        self.regs = LEAPClusterRegs(u, base)
        self.core_regs = [
            LEAPCoreRegs(u, base + 0x100_000 * i)
            for i in range(ncores)
        ]
        self.cores = [
            LEAP(self, regs, no)
            for no, regs in enumerate(self.core_regs)
        ]
