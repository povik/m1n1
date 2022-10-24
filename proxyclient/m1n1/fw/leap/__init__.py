from enum import IntEnum, IntFlag
from construct import *

from m1n1.utils import Register32, RegAdapter

class LEAPFROGSectionType(IntEnum):
    STATE0 = 0x10000
    STATE1 = 0x10001
    STATE2 = 0x10002
    STATE3 = 0x10003

    INST0 = 0x20000
    INST1 = 0x20001
    INST2 = 0x20002
    INST3 = 0x20003

    WAITEMPTY_LIST = 0x30000
    WAITFULL_LIST  = 0x30001

class LEAPFROGSectionFlags(Register32):
    ROUTINE = 0

LEAPFROGSection = Struct(
    "type" / Enum(Int32ul, LEAPFROGSectionType),
    "load_base" / Int32ul,
    "size" / Int32ul,
    "flags" / Default(RegAdapter(LEAPFROGSectionFlags),
                      LEAPFROGSectionFlags(0)),
    "data" / Int32ul[this.size],
)

LEAPFROGImage = Struct(
    "magic" / Const(0x1ea9, Int16ul),
    "fmtversion" / Const(0, Int16ul),
    "nsections" / Int32ul,
    "section" / LEAPFROGSection[this.nsections], 
)

def save_leapfrog_image(cluster, f):
    sections = []

    for i, bank in enumerate([cluster.regs.STATE0,
                    cluster.regs.STATE1, cluster.regs.STATE2,
                    cluster.regs.STATE3]):
        data = cluster.read_bank(bank)
        print(i, len(data))
        sections.append(Container(
            type=LEAPFROGSectionType.STATE0 + i,
            load_base=0,
            size=len(data),
            data=data,
        ))

    for i in range(8):
        if not cluster.regs.ROUTINE_CTL.reg.LOADED & (1 << i):
            continue

        limits = cluster.PC_LIMITS[i].reg
        span = range(limits.BOT, limits.TOP)

        sections += [
            Container(
                type=LEAPFROGSectionType.INST0 + partno,
                load_base=span.start,
                size=len(span),
                flags=LEAPFROGSectionFlags(ROUTINE=1),
                data=[regs[p].val for p in span],
            ) for partno, regs in enumerate([
                cluster.regs.PROGRAM0, cluster.regs.PROGRAM1,
                cluster.regs.PROGRAM2, cluster.regs.PROGRAM3,
            ])
        ]

    image = Container(
        nsections=len(sections),
        section=sections,
    )

    if type(f) is str:
        with open(f, "wb") as f:
            LEAPFROGImage.build_stream(image, f)
    else:
        LEAPFROGImage.build_stream(image, f)

def load_leapfrog_image(core, f):
    if type(f) in [bytes, bytearray]:
        image = LEAPFROGImage.parse(f)
    elif type(f) is str:
        with open(f, "rb") as f:
            image = LEAPFROGImage.parse_stream(f)
    else:
        image = LEAPFROGImage.parse_stream(f)

    regs = core.regs
    routine_spans = set()
    for section in image.section:
        if section.flags.ROUTINE:
            routine_spans.add((section.load_base,
                               section.load_base + section.size))

        Section = LEAPFROGSectionType
        if section.type in ["WAITFULL_LIST", "WAITEMPTY_LIST"]:
            continue

        section_banks = {
            "STATE0": regs.STATE0,
            "STATE1": regs.STATE1,
            "STATE2": regs.STATE2,
            "STATE3": regs.STATE3,
            "INST0": regs.INST0,
            "INST1": regs.INST1,
            "INST2": regs.INST2,
            "INST3": regs.INST3,
        }

        core.write_bank(section_banks[section.type], section.data,
                        base=section.load_base)

    spanidx = 0
    routidx_by_base = {}
    for span in sorted(list(routine_spans)):
        regs.PC_LIMITS[spanidx].set(TOP=span[1], BOT=span[0])
        routidx_by_base[span[0]] = spanidx
        spanidx += 1

    for section in image.section:
        Section = LEAPFROGSectionType
        if int(section.type) == Section.WAITFULL_LIST:
            r = core.parent.regs.WAITFULL_SIEVE
        elif int(section.type) == Section.WAITEMPTY_LIST:
            r = core.parent.regs.WAITEMPTY_SIEVE
        else:
            continue

        routidx = routidx_by_base[section.load_base >> 16]
        for regno in range(4):
            r[core.no, routidx, regno].val = sum([1 << p >> (regno * 32) for p in section.data]) & ~(-1 << 32)

