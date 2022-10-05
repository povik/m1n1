# SPDX-License-Identifier: MIT
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
        #self.add_mon()
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

    def add_mon(self):
        if self.state.shmem_iova:
            iomon.add(self.state.shmem_iova, 32768,
                      name=f"{self.name}.shmem@{self.state.shmem_iova:08x}", offset=0)

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
        #self.add_mon()

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

    def read_resp(self, f, logger=None):
        if logger is None:
            logger = print
        self.rets = self.RETS.parse_stream(f)
        self.dump(logger)

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
class SetPowerState(WrappedCall):
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
        "unk3" / Hex(Int32ul),
        "devid_again" / FourCC,
        "unk4" / Hex(Int32ul),
        "unk5" / Hex(Int32ul),
        "unk" / HexDump(GreedyBytes),
        #"blank2" / ZPadding(8),
        #"target" / FourCC,
        #"unk6" / Hex(Int32ul),
        #"blank3" / ZPadding(20),
    )
    RETS = Struct(
        "unk" / HexDump(GreedyBytes),
    )

@WrappedCall.reg_subclass
class AddDevice(WrappedCall):
    CALLTYPE = 0xc3_00_00_02
    ARGS = Struct(
        "blank" / Const(0x0, Int32ul),
        "unk1" / Hex(Const(0xffffffff, Int32ul)),
        "calltype" / Hex(Int32ul),
        "blank2" / ZPadding(16),
        "pad" / Hex(Int32ul),
        "len" / Hex(Int64ul),
        "devid" / FourCC,
        "unk2" / Hex(Int32ul), # can be found in debug prints
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
class GetPowerState(WrappedCall):
    CALLTYPE = 0xc3_00_00_04
    ARGS = Struct(
        "blank" / Const(0x0, Int32ul),
        "unk1" / Hex(Const(0xffffffff, Int32ul)),
        "calltype" / Hex(Int32ul),
        "blank2" / ZPadding(16),
        "pad" / Hex(Int32ul),
        "len" / Hex(Int64ul),
        "devid" / FourCC,
        "modifier" / Enum(Int32ul,
            ORDINARY=200,
            CLOCK_DOMAIN=203,
        ),
        "unk6" / Hex(Const(0x01, Int32ul)),
    )
    RETS = Struct(
        "blank" / Const(0x0, Int32ul),
        #"unk1" / Const(0x4, Int32ul),
        "unk1" / Int32ul,
        "state" / FourCC,
    )

@reg_calltype
class IndirectCall(EPICCall):
    ARGS = EPICCmd
    RETS = EPICCmd

    @classmethod
    def matches(cls, hdr, sub):
        return sub.category == EPICCategory.COMMAND

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

    def handle_call(self, hdr, sub, fd):
        for calltype in CALLTYPES:
            if calltype.matches(hdr, sub):
                try:
                    self.pending_call = calltype.from_stream(fd)
                except Exception as e:
                    self.log(f"failed parsing ({calltype.__name__}): {e}")
                    return False
                return True

        return False

    def handle_reply(self, hdr, sub, fd):
        if self.pending_call is None:
            return False

        try:
            self.pending_call.read_resp(fd, logger=self.log)
        except Exception as e:
            self.log(f"failed parsing: {e}")
        self.pending_call = None
        return True

    def dispatch_ipc(self, dir, hdr, sub, fd):
        if sub.category == EPICCategory.COMMAND:
            return self.handle_call(hdr, sub, fd)
        if dir == "<" and sub.category == EPICCategory.REPORT:
            return self.handle_hello(hdr, sub, fd)
        if dir == ">" and sub.category == EPICCategory.NOTIFY:
            return self.handle_call(hdr, sub, fd)
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
    def replay(cls, f):
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

        for l in f:
            if (rxhdr := "===RX DATA===") in l:
                dir = "<"
                hdr = rxhdr
            elif (txhdr := "===TX DATA===") in l:
                dir = ">"
                hdr = txhdr
            else:
                #print(l, end="")
                continue

            fields_str = l[l.index(hdr) + len(hdr):]
            fields = dict([s.split("=") for s in fields_str.strip().split(" ")])
            epid = int(fields["epid"])

            datadump = ""
            for l in f:
                if "===END DATA===" in l:
                    break
                datadump += l

            data = chexundump(datadump)
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
