from ..hw.dart import *
from ..hw.admac import *
from ..hv import TraceMode
from ..utils import *
from . import ADTDevTracer

class ADMACTracer(ADTDevTracer):
    DEFAULT_MODE = TraceMode.RESERVED

    REGMAPS = [ADMACRegs]
    NAMES = ["regs"]

    def __init__(self, hv, devpath, verbose=False):
        super().__init__(hv, devpath, verbose)
        self.dart = None
        self.dart_stream = 0
        self.monitors = dict()

    @classmethod
    def _reloadcls(cls):
        global ADMADescriptor
        ADMADescriptor = ADMADescriptor._reloadcls()
        global ADMAReport
        ADMAReport = ADMAReport._reloadcls()
        return super()._reloadcls()

    def init_state(self):
        # TODO: clear _in_progress on reset
        self.state._in_progress = dict()
        self.state._report_pieces = dict()
        self.state._desc_pieces = dict()

    def start(self):
        if len(self.monitors) and self.dart is None:
            raise Exception("need DART reference to feed monitors")
        super().start()
        if len(self.monitors):
            self.hv.p.hv_map_admac_tracer(self.dev.get_reg(0)[0])

    def submit(self, channo, desc):
        self.state._in_progress[(channo, desc.flags.DESC_ID)] = desc

    def retire(self, channo, report):
        idx = (channo, report.flags.DESC_ID)

        if idx not in self.state._in_progress:
            self.log(f"Stray report {idx}!")
            return

        desc = self.state._in_progress[idx]

        if channo in self.monitors:
            m = self.monitors[channo]
            buf = self.dart.ioread(self.dart_stream,
                                   desc.addr, desc.length)
            m.write(buf)

    def r_TX_REPORT_READ(self, piece, idx):
        channo = idx * 2
        prior = self.state._report_pieces.get(channo, [])
        pieces = prior + [int(piece)]

        if len(pieces) != 4:
            self.state._report_pieces[channo] = pieces
            return

        try:
            report = ADMACReport.deser(pieces)
            self.log(f"(ch{channo}) Read report: {report}")

        except ValueError:
            self.log(f"(ch{channo}) Bad report with pieces {pieces}")
        finally:
            self.retire(channo, report)

        del self.state._report_pieces[channo]

    def w_TX_DESC_WRITE(self, piece, idx):
        channo = idx * 2
        prior = self.state._desc_pieces.get(channo, [])
        pieces = prior + [int(piece)]

        if len(pieces) != 4:
            self.state._desc_pieces[channo] = pieces
            return

        try:
            desc = ADMACDescriptor.deser(pieces)
            self.log(f"(ch{channo}) Wrote descriptor: {desc}")
            self.submit(channo, desc)
        except ValueError:
            self.log(f"(ch{channo}) Bad descriptor with pieces {pieces}")

        del self.state._desc_pieces[channo]
