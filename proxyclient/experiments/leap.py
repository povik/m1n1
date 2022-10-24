#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import sys, pathlib
sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))

import struct
import traceback
from construct import *

from m1n1.setup import *
from m1n1.shell import run_shell
from m1n1.hw.leap import LEAP

mon = RegMonitor(u, bufsize=0x500000)

if False:
	p.write32(0x292284000 + 4 * 8, 0xf); # LEAP_CLK
	p.write32(0x292284000 + 16 * 8, 0xf); # LEAP
	leap_base = 0x294000000
else:
	p.write32(0x23d284030, 0xf) # LEAP_AOPCLK
	p.write32(0x23d2840b8, 0xf) # LEAP
	leap_base = 0x24b000000

#mon.add(leap_base, 0x400000, name="leap0")
mon.add(leap_base, 0x200000, name="leap0")
l = LEAP(u, leap_base)

run_shell(locals())
