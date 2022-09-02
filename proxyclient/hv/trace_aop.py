# SPDX-License-Identifier: MIT
from m1n1.trace import Tracer
from m1n1.trace.dart import DARTTracer
from m1n1.trace.asc import ASCTracer, EP, EPState, msg, msg_log, DIR
from m1n1.utils import *
from m1n1.fw.afk.rbep import *
from m1n1.fw.afk.epic import *

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
            if self.state.verbose >= 3:
                self.log(f">TX rptr={self.txbuf.state.rptr:#x}")
                chexdump(data)
            self.handle_ipc(data, dir=">")
        return True

    Hello =         msg_log(0xa3, DIR.TX)

    @msg(0x85, DIR.RX, AFKEPMessage)
    def Recv(self, msg):
        for data in self.rxbuf.read():
            if self.state.verbose >= 3:
                self.log(f"<RX rptr={self.rxbuf.state.rptr:#x}")
                chexdump(data)
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


EPICCategoryVer2 = "EPICCategory" / Enum(Int8ul,
    CALL = 0x10,
    REPLY = 0x20,
)

EPICSubHeaderVer2 = Struct(
    "length" / Int32ul,
    "version" / Default(Int8ul, 2),
    "category" / EPICCategoryVer2,
    "type" / Hex(Int16ul),
    "timestamp" / Default(Int64ul, 0),
    "unk" / Default(Hex(Int64ul), 0)
)

class EPICEp(AFKEp):
    def handle_ipc(self, data, dir=None):
        fd = BytesIO(data)
        hdr = EPICHeader.parse_stream(fd)
        sub = EPICSubHeaderVer2.parse_stream(fd)

        self.log(f"{dir} {hdr.channel} Type {hdr.type} Ver {hdr.version} Tag {hdr.seq}")
        self.log(f"  Len {sub.length} Ver {sub.version} Cat {sub.category} Type {sub.type:#x} Ts {sub.timestamp:#x}")
        self.log(f"  Unk {sub.unk:#x}")
        chexdump(data)

        #if sub.category == EPICCategory.REPORT:
        #    self.handle_report(hdr, sub, fd)
        #if sub.category == EPICCategory.NOTIFY:
        #    self.handle_notify(hdr, sub, fd)
        #elif sub.category == EPICCategory.REPLY:
        #    self.handle_reply(hdr, sub, fd)
        #elif sub.category == EPICCategory.COMMAND:
        #    self.handle_cmd(hdr, sub, fd)

    def handle_report(self, hdr, sub, fd):
        if sub.type == 0x30:
            init = EPICAnnounce.parse_stream(fd)
            self.log(f"Init: {init.name}")
            self.log(f"  Props: {init.props}")
        else:
            self.log(f"Report {sub.type:#x}")
            chexdump(fd.read())

    def handle_notify(self, hdr, sub, fd):
        self.log(f"Notify:")
        chexdump(fd.read())

    def handle_reply(self, hdr, sub, fd):
        try:
            cmd = EPICCmd.parse_stream(fd)
            payload = fd.read()
        except:
            self.log("Failed to parse reply")
            return
        self.log(f"Response {sub.type:#x}: {cmd.retcode:#x}")
        if payload:
            self.log("Inline payload:")
            chexdump(payload)
        if cmd.rxbuf:
            self.log(f"RX buf @ {cmd.rxbuf:#x} ({cmd.rxlen:#x} bytes):")
            chexdump(self.dart.ioread(0, cmd.rxbuf, cmd.rxlen))

    def handle_cmd(self, hdr, sub, fd):
        cmd = EPICCmd.parse_stream(fd)
        payload = fd.read()
        self.log(f"Command {sub.type:#x}: {cmd.retcode:#x}")
        if payload:
            chexdump(payload)
        if cmd.txbuf:
            self.log(f"TX buf @ {cmd.txbuf:#x} ({cmd.txlen:#x} bytes):")
            chexdump(self.dart.ioread(0, cmd.txbuf, cmd.txlen))


class UNK20Ep(DummyAFKEp):
    SHORT = "unk20"

class UNK21Ep(DummyAFKEp):
    SHORT = "unk21"

class UNK22Ep(DummyAFKEp):
    SHORT = "unk22"

class UNK24Ep(DummyAFKEp):
    SHORT = "unk23"

class UNK25Ep(DummyAFKEp):
    SHORT = "unk24"

class UNK26Ep(DummyAFKEp):
    SHORT = "unk25"

class UNK27Ep(DummyAFKEp):
    SHORT = "unk26"

class AOPAudioEp(EPICEp):
    SHORT = "audio-aop"

class UNK28Ep(DummyAFKEp):
    SHORT = "unk28"

class AOPTracer(ASCTracer):
    ENDPOINTS = {
        0x20: UNK20Ep,
        0x21: UNK21Ep,
        0x22: UNK22Ep,
        0x24: UNK24Ep,
        0x25: UNK25Ep,
        0x26: UNK26Ep,
        0x27: AOPAudioEp,
        0x28: UNK28Ep,
    }

dart_aop_tracer = DARTTracer(hv, "/arm-io/dart-aop", verbose=4)
dart_aop_tracer.start()

dart_aop_base = u.adt["/arm-io/dart-aop"].get_reg(0)[0]

hv.trace_range(irange(*u.adt["/arm-io/aop"].get_reg(1)))
hv.trace_range(irange(*u.adt["/arm-io/aop"].get_reg(2)))
hv.trace_range(irange(*u.adt["/arm-io/aop"].get_reg(3)))

aop_tracer = AOPTracer(hv, "/arm-io/aop", verbose=1)
aop_tracer.start(dart_aop_tracer.dart)
