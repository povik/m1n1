# SPDX-License-Identifier: MIT

from m1n1.proxyutils import RegMonitor
from m1n1.trace import Tracer
from m1n1.trace.dart import DARTTracer
from m1n1.trace.asc import ASCTracer, EP, EPState, msg, msg_log, DIR, EPContainer
from m1n1.utils import *
from m1n1.constructutils import *
from m1n1.fw.afk.rbep import *
from m1n1.fw.afk.epic import *

import sys

class AOPAudioPropKey(IntEnum):
    IS_READY = 0x01

    UNK_11 = 0x11
    PLACEMENT = 0x1e
    UNK_21 = 0x21
    ORIENTATION = 0x2e
    LOCATION_ID = 0x30
    SERIAL_NO = 0x3e
    VENDOR_ID = 0x5a
    PRODUCT_ID = 0x5b

    SERVICE_CONTROLLER = 0x64
    DEVICE_COUNT = 0x65

    VERSION = 0x67

class AFKRingBufSniffer(AFKRingBuf):
    def __init__(self, ep, state, base, size):
        super().__init__(ep, base, size)
        self.state = state
        self.rptr = getattr(state, "rptr", 0)

    def update_rptr(self, rptr):
        self.state.rptr = rptr

    def update_wptr(self):
        raise NotImplementedError()

    def get_wptr(self):
        return struct.unpack("<I", self.read_buf(2 * self.BLOCK_SIZE, 4))[0]

    def read_buf(self, off, size):
        return self.ep.dart.ioread(0, self.base + off, size)

class AFKEp(EP):
    BASE_MESSAGE = AFKEPMessage

    def __init__(self, tracer, epid):
        super().__init__(tracer, epid)
        self.txbuf = None
        self.rxbuf = None
        self.state.txbuf = EPState()
        self.state.rxbuf = EPState()
        self.state.shmem_iova = None
        self.state.txbuf_info = None
        self.state.rxbuf_info = None
        self.state.verbose = 1

    def start(self):
        self.create_bufs()

    def create_bufs(self):
        if not self.state.shmem_iova:
            return
        if not self.txbuf and self.state.txbuf_info:
            off, size = self.state.txbuf_info
            self.txbuf = AFKRingBufSniffer(self, self.state.txbuf,
                                           self.state.shmem_iova + off, size)
        if not self.rxbuf and self.state.rxbuf_info:
            off, size = self.state.rxbuf_info
            self.rxbuf = AFKRingBufSniffer(self, self.state.rxbuf,
                                           self.state.shmem_iova + off, size)

    Init =          msg_log(0x80, DIR.TX)
    Init_Ack =      msg_log(0xa0, DIR.RX)

    GetBuf =        msg_log(0x89, DIR.RX)

    Shutdown =      msg_log(0xc0, DIR.TX)
    Shutdown_Ack =  msg_log(0xc1, DIR.RX)

    @msg(0xa1, DIR.TX, AFKEP_GetBuf_Ack)
    def GetBuf_Ack(self, msg):
        self.state.shmem_iova = msg.DVA
        self.txbuf = None
        self.rxbuf = None
        self.state.txbuf = EPState()
        self.state.rxbuf = EPState()
        self.state.txbuf_info = None
        self.state.rxbuf_info = None

    @msg(0xa2, DIR.TX, AFKEP_Send)
    def Send(self, msg):
        for data in self.txbuf.read():
            #if self.state.verbose >= 3:
            if True:
                self.log(f"===TX DATA=== epid={self.epid} rptr={self.txbuf.state.rptr:#x}")
                chexdump(data)
                self.log(f"===END DATA===")
                self.log("Backtrace on TX data:")
                self.hv.bt()
            self.handle_ipc(data, dir=">")
        return True

    Hello =         msg_log(0xa3, DIR.TX)

    @msg(0x85, DIR.RX, AFKEPMessage)
    def Recv(self, msg):
        for data in self.rxbuf.read():
            #if self.state.verbose >= 3:
            if True:
                self.log(f"===RX DATA=== epid={self.epid} rptr={self.rxbuf.state.rptr:#x}")
                chexdump(data)
                self.log(f"===END DATA===")
            self.handle_ipc(data, dir="<")
        return True

    def handle_ipc(self, data, dir=None):
        pass

    @msg(0x8a, DIR.RX, AFKEP_InitRB)
    def InitTX(self, msg):
        off = msg.OFFSET * AFKRingBuf.BLOCK_SIZE
        size = msg.SIZE * AFKRingBuf.BLOCK_SIZE
        self.state.txbuf_info = (off, size)
        self.create_bufs()

    @msg(0x8b, DIR.RX, AFKEP_InitRB)
    def InitRX(self, msg):
        off = msg.OFFSET * AFKRingBuf.BLOCK_SIZE
        size = msg.SIZE * AFKRingBuf.BLOCK_SIZE
        self.state.rxbuf_info = (off, size)
        self.create_bufs()

class DummyAFKEp(AFKEp):
    def handle_ipc(self, data, dir=None):
        pass

EPICSubHeaderVer2 = Struct(
    "length" / Int32ul,
    "version" / Default(Int8ul, 2),
    "category" / EPICCategory,
    "type" / Hex(Int16ul),
    "timestamp" / Default(Int64ul, 0),
    "unk1" / Default(Hex(Int32ul), 0),
    "unk2" / Default(Hex(Int32ul), 0),
)

class EPICCall:
    @classmethod
    def matches(cls, hdr, sub):
        return int(sub.type) == cls.TYPE and int(sub.unk2) == cls.UNK2

    def __init__(self, args):
        #assert type(args) is self.ARGS
        self.args = args
        self.rets = None

    @classmethod
    def from_stream(cls, f):
        return cls(cls.ARGS.parse_stream(f))

    def dump(self, logger):
        args_fmt = [f"{k}={v}" for (k, v) in self.args.items() if k != "_io"]
        rets_fmt = [f"{k}={v}" for (k, v) in self.rets.items() if k != "_io"]
        logger(f"{type(self).__name__}({', '.join(args_fmt)}) -> ({', '.join(rets_fmt)})")

    def read_resp(self, f):
        self.rets = self.RETS.parse_stream(f)

CALLTYPES = []
def reg_calltype(calltype):
    CALLTYPES.append(calltype)
    return calltype

@reg_calltype
class GetHIDDescriptor(EPICCall):
    TYPE = 0x1
    UNK2 = 228
    ARGS = Struct(
        "blank" / Const(0x0, Int32ul),
    )
    RETS = Struct(
        "blank" / Const(0x0, Int32ul),
        "descriptor" / HexDump(GreedyBytes),
    )

@reg_calltype
class GetProperty(EPICCall):
    TYPE = 0xa
    ARGS = Struct(
        "blank" / Const(0x0, Int32ul),
        "key" / Enum(Int32ul, AOPAudioPropKey),
    )
    RETS = Struct(
        #"blank" / Const(0x0, Int32ul),
        "value" / GreedyBytes,
    )

    @classmethod
    def matches(cls, hdr, sub):
        # don't match on unk2
        return sub.type == cls.TYPE

@reg_calltype
class WrappedCall(EPICCall):
    SUBCLASSES = {}
    TYPE = 0x20
    HDR = Struct(
        "blank" / Const(0x0, Int32ul),
        "unk1" / Hex(Const(0xffffffff, Int32ul)),
        "calltype" / Hex(Int32ul),
        "blank2" / ZPadding(16),
        "pad" / Hex(Int32ul),
        "len" / Hex(Int64ul),
        "residue" / HexDump(GreedyBytes),
    )

    @classmethod
    def from_stream(cls, f):
        payload = f.read()
        subsub = cls.HDR.parse(payload)
        calltype = int(subsub.calltype)
        subcls = cls.SUBCLASSES.get(calltype, None)
        if subcls is None:
            raise ValueError(f"unknown calltype {calltype:#x}")
        return subcls(subcls.ARGS.parse(payload))

    @classmethod
    def reg_subclass(cls, cls2):
        cls.SUBCLASSES[int(cls2.CALLTYPE)] = cls2

    @classmethod
    def matches(cls, hdr, sub):
        # don't match on unk2
        return sub.category == EPICCategory.NOTIFY and sub.type == cls.TYPE

@WrappedCall.reg_subclass
class StartDevice(WrappedCall):
    CALLTYPE = 0xc3_00_00_02
    ARGS = Struct(
        "blank" / Const(0x0, Int32ul),
        "unk1" / Hex(Const(0xffffffff, Int32ul)),
        "calltype" / Hex(Int32ul),
        "blank2" / ZPadding(16),
        "pad" / Hex(Int32ul),
        "len" / Hex(Int64ul),
        "devid" / FourCC,
        "pad" / Hex(Int32ul),
    )
    RETS = Struct(
        "unk" / HexDump(GreedyBytes),
    )

@WrappedCall.reg_subclass
class ProbeDevice(WrappedCall):
    CALLTYPE = 0xc3_00_00_01
    ARGS = Struct(
        "blank" / Const(0x0, Int32ul),
        "unk1" / Hex(Const(0xffffffff, Int32ul)),
        "calltype" / Hex(Int32ul),
        "blank2" / ZPadding(16),
        "pad" / Hex(Int32ul),
        "len" / Hex(Int64ul),
        "devno" / Int32ul,
    )
    RETS = Struct(
        "blank" / Const(0x0, Int32ul),
        "devid" / FourCC,
        "blank2" / Const(0x0, Int32ul),
        "unk1" / Const(8, Int32ul),
        "blank3" / Const(0x0, Int32ul),
        "unk2" / Hex(Const(0x01_0d_1c_20, Int32ul)),
        "blank4" / Const(0x0, Int32ul),
        "unk3" / Hex(Enum(
            Int32ul,
            A = 0x85146502,
            B = 0x0109B7D8,
            C = 0x01051284,
        )),
        "unk" / HexDump(GreedyBytes),
    )

@WrappedCall.reg_subclass
class GetDeviceProp(WrappedCall):
    CALLTYPE = 0xc3_00_00_04
    ARGS = Struct(
        "blank" / Const(0x0, Int32ul),
        "unk1" / Hex(Const(0xffffffff, Int32ul)),
        "calltype" / Hex(Int32ul),
        "blank2" / ZPadding(16),
        "pad" / Hex(Int32ul),
        "len" / Hex(Int64ul),
        "devid" / FourCC,
        "modifier" / Int32ul,
        # Enum(Int32ul, ORDINARY=200, CLOCK_DOMAIN=203,),
        "unk6" / Hex(Const(0x01, Int32ul)),
    )
    RETS = Struct(
        "blank" / Const(0x0, Int32ul),
        #"unk1" / Const(0x4, Int32ul),
        "unk1" / Int32ul,
        "state" / FourCC,
    )

@WrappedCall.reg_subclass
class SetDeviceProp(WrappedCall):
    CALLTYPE = 0xc3_00_00_05
    ARGS = Struct(
        "blank" / Const(0x0, Int32ul),
        "unk1" / Hex(Const(0xffffffff, Int32ul)),
        "calltype" / Hex(Int32ul),
        "blank2" / ZPadding(16),
        "pad" / Hex(Int32ul),
        "len" / Hex(Int64ul),
        "devid" / FourCC,
        "modifier" / Int32ul,
        "len2" / Hex(Const(len_(this.data), Int32ul)),
        "data" / Switch(this.modifier, {
            200: Struct(
                "unk1" / Int32ul,
                "clockSource" / FourCC,
                "pdmFrequency" / Int32ul,
                "unk3_clk" / Int32ul,
                "unk4_clk" / Int32ul,
                "unk5_clk" / Int32ul,
                "channelPolaritySelect" / Hex(Int32ul),
                "unk7" / Hex(Int32ul),
                "unk8" / Hex(Int32ul),
                "unk9" / Hex(Int16ul),
                "ratios" / Struct(
                    "r1" / Int8ul,
                    "r2" / Int8ul,
                    "r3" / Int8ul,
                    "pad" / Int8ul,
                ),
                "filterLengths" / Hex(Int32ul),
                "coeff_bulk" / Int32ul,
                "coefficients" / Struct(
                    "c1" / Int32sl[this._.ratios.r3 * 4 + 4],
                    "c2" / Int32sl[this._.ratios.r2 * 4 + 4],
                    "c3" / Int32sl[this._.ratios.r1 * 4 + 4],
                ),
                "junk" / Hex(Int32ul[
                    this.coeff_bulk - 12 \
                    - (this.ratios.r1 + this.ratios.r2 + this.ratios.r3) * 4
                ]),
                "unk10" / Int32ul, # maybe
                "micTurnOnTimeMs" / Int32ul,
                "blank" / ZPadding(16),
                "unk11" / Int32ul,
                "micSettleTimeMs" / Int32ul,
                "blank2" / ZPadding(69),
            ),
            210: Struct(
                "latency" / Int32ul,
                "ratios" / Struct(
                    "r1" / Int8ul,
                    "r2" / Int8ul,
                    "r3" / Int8ul,
                    "pad" / Int8ul,
                ),
                "filterLengths" / Hex(Int32ul),
                "coeff_bulk" / Int32ul,
                "coefficients" / Struct(
                    "c1" / Int32sl[this._.ratios.r3 * 4 + 4],
                    "c2" / Int32sl[this._.ratios.r2 * 4 + 4],
                    "c3" / Int32sl[this._.ratios.r1 * 4 + 4],
                ),
                "junk" / Hex(Int32ul[
                    this.coeff_bulk - 12 \
                    - (this.ratios.r1 + this.ratios.r2 + this.ratios.r3) * 4
                ]),
            ),
        }, default=HexDump(GreedyBytes))
    )
    RETS = Struct(
        "unk" / HexDump(GreedyBytes),
    )

@reg_calltype
class IndirectCall(EPICCall):
    ARGS = EPICCmd
    RETS = EPICCmd

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.txbuf = None
        self.rxbuf = None

    @classmethod
    def matches(cls, hdr, sub):
        return sub.category == EPICCategory.COMMAND

    def read_resp(self, f):
        self.rets = self.RETS.parse_stream(f)

    def read_txbuf(self, ep):
        cmd = self.args
        # TODO: how come we need this?
        ep.dart.invalidate_cache()
        self.txbuf = ep.dart.ioread(0, cmd.txbuf, cmd.txlen)

        ep.log(f"===COMMAND TX DATA=== addr={cmd.txbuf:#x}")
        chexdump(self.txbuf)
        ep.log(f"===END DATA===")

    def read_rxbuf(self, ep):
        cmd = self.rets
        ep.dart.invalidate_cache()
        self.rxbuf = ep.dart.ioread(0, cmd.rxbuf, cmd.rxlen)

        ep.log(f"===COMMAND RX DATA=== addr={cmd.rxbuf:#x}")
        chexdump(self.rxbuf)
        ep.log(f"===END DATA===")

    def unwrap(self):
        fd = BytesIO()
        fd.write(b"\x00\x00\x00\x00")
        fd.write(self.txbuf)
        fd.seek(0)
        wrapped = WrappedCall.from_stream(fd)
        fd = BytesIO()
        fd.write(b"\x00\x00\x00\x00")
        fd.write(self.rxbuf)
        fd.seek(0)
        wrapped.read_resp(fd)
        return wrapped

class EPICEp(AFKEp):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pending_call = None
        self.pending_cmd = None

    def handle_hello(self, hdr, sub, fd):
        if sub.type != 0xc0:
            return False

        payload = fd.read()
        name = payload.split(b"\0")[0].decode("ascii")
        self.log(f"Hello! (endpoint {name})")
        return True

    def handle_notify(self, hdr, sub, fd):
        for calltype in CALLTYPES:
            if calltype.matches(hdr, sub):
                call = calltype.from_stream(fd)
                self.trace_call_early(call)
                self.pending_call = call
                return True

        return False

    def handle_reply(self, hdr, sub, fd):
        if self.pending_call is None:
            return False

        call = self.pending_call
        call.read_resp(fd)
        self.trace_call(call)
        self.pending_call = None
        return True

    def dispatch_ipc(self, dir, hdr, sub, fd):
        if sub.category == EPICCategory.COMMAND:
            return self.handle_notify(hdr, sub, fd)
        if dir == "<" and sub.category == EPICCategory.REPORT:
            return self.handle_hello(hdr, sub, fd)
        if dir == ">" and sub.category == EPICCategory.NOTIFY:
            return self.handle_notify(hdr, sub, fd)
        if dir == "<" and sub.category == EPICCategory.REPLY:
            return self.handle_reply(hdr, sub, fd)

    def handle_ipc(self, data, dir=None):
        fd = BytesIO(data)
        hdr = EPICHeader.parse_stream(fd)
        sub = EPICSubHeaderVer2.parse_stream(fd)

        if not getattr(self, 'VERBOSE', False):
            return

        if self.dispatch_ipc(dir, hdr, sub, fd):
            return

        self.log(f"{dir} 0x{hdr.channel:x} Type {hdr.type} Ver {hdr.version} Tag {hdr.seq}")
        self.log(f"  Len {sub.length} Ver {sub.version} Cat {sub.category} Type {sub.type:#x} Ts {sub.timestamp:#x}")
        self.log(f"  Unk1 {sub.unk1:#x} Unk2 {sub.unk2:#x}")
        chexdump(fd.read())

    def trace_call_early(self, call):
        # called at TX time
        if isinstance(call, IndirectCall):
            call.read_txbuf(self)

    def trace_call(self, call):
        if isinstance(call, IndirectCall):
            call.read_rxbuf(self)
            self.log("Unwrapping indirect (see below)")
            call.dump(self.log)
            call = call.unwrap()
            #self.log("TX")
            #chexdump(call.txbuf)
            #self.log("RX")
            #chexdump(call.rxbuf)
        call.dump(self.log)

class SPUAppEp(EPICEp):
    SHORT = "SPUApp"

class AccelEp(EPICEp):
    SHORT = "accel"

class GyroEp(EPICEp):
    SHORT = "gyro"

class LASEp(EPICEp):
    SHORT = "las"

class WakeHintEp(EPICEp):
    SHORT = "wakehint"

class UNK26Ep(EPICEp):
    SHORT = "unk26"

class AudioEp(EPICEp):
    SHORT = "aop-audio"
    VERBOSE = True

class VoiceTriggerEp(EPICEp):
    SHORT = "aop-voicetrigger"

class AOPTracer(ASCTracer):
    ENDPOINTS = {
        0x20: SPUAppEp,
        0x21: AccelEp,
        0x22: GyroEp,
        0x24: LASEp,
        0x25: WakeHintEp,
        0x26: UNK26Ep,
        0x27: AudioEp,
        0x28: VoiceTriggerEp,
    }

    @classmethod
    def replay(cls, f, passthru=True):
        epmap = dict()
        epcont = EPContainer()

        class FakeASCTracer:
            def __init__(self):
                self.hv = None

            def log(self, str):
                print(str)
        asc_tracer = FakeASCTracer()

        for cls in cls.mro():
            eps = getattr(cls, "ENDPOINTS", None)
            if eps is None:
                break
            for k, v in eps.items():
                if k in epmap:
                    continue
                ep = v(asc_tracer, k)
                epmap[k] = ep
                if getattr(epcont, ep.name, None):
                    ep.name = f"{ep.name}{k:02x}"
                setattr(epcont, ep.name, ep)
                ep.start()

        def readdump(firstline, hdr, f):
            l = firstline
            assert hdr in l
            postscribe = l[l.index(hdr) + len(hdr):]
            annotation = dict([s.split("=") for s \
                              in postscribe.strip().split(" ")])

            dump = []
            for l in f:
                if "===END DATA===" in l:
                    break
                dump.append(l)
            return chexundump("".join(dump)), annotation

        # hook command buffer reads
        def read_txbuf(icall, ep):
            hdr = "===COMMAND TX DATA==="
            for l in f:
                if hdr in l:
                    break
            data, annot = readdump(l, hdr, f)
            assert int(annot["addr"], 16) == icall.args.txbuf
            icall.txbuf = data
        def read_rxbuf(icall, ep):
            hdr = "===COMMAND RX DATA==="
            for l in f:
                if hdr in l:
                    break
            data, annot = readdump(l, hdr, f)
            assert int(annot["addr"], 16) == icall.rets.rxbuf
            icall.rxbuf = data
        IndirectCall.read_rxbuf = read_rxbuf
        IndirectCall.read_txbuf = read_txbuf

        for l in f:
            if (rxhdr := "===RX DATA===") in l:
                dir = "<"
                hdr = rxhdr
            elif (txhdr := "===TX DATA===") in l:
                dir = ">"
                hdr = txhdr
            else:
                if passthru:
                    print(l, end="")
                continue
            data, annot = readdump(l, hdr, f)
            epid = int(annot["epid"])
            epmap[epid].handle_ipc(data, dir)
                        

if __name__ == "__main__":
    with open(sys.argv[1]) as f:
        AOPTracer.replay(f)
    sys.exit(0)

dart_aop_tracer = DARTTracer(hv, "/arm-io/dart-aop", verbose=4)
dart_aop_tracer.start()

dart_aop_base = u.adt["/arm-io/dart-aop"].get_reg(0)[0]

hv.trace_range(irange(*u.adt["/arm-io/aop"].get_reg(1)))
hv.trace_range(irange(*u.adt["/arm-io/aop"].get_reg(2)))
hv.trace_range(irange(*u.adt["/arm-io/aop"].get_reg(3)))

aop_tracer = AOPTracer(hv, "/arm-io/aop", verbose=1)
aop_tracer.start(dart_aop_tracer.dart)
