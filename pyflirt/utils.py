#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from x64dbgpy3.x64dbgpy3 import *

class utils:
    @staticmethod
    def read(addr, size):
        return dbgMemory.Read(addr, size)

    @staticmethod
    def code(addr):
        return dbgMisc.ParseExpression("mem.iscode({:x})".format(addr))

    @staticmethod
    def call(addr):
        return dbgMisc.ParseExpression("dis.branchdest({:x})".format(addr))

    def next(addr):
        return dbgMisc.ParseExpression("dis.next({:x})".format(addr))


    class signinfo:
        name: str=''

    @staticmethod
    def exec_formblock(buffer, base=0):
        from capstone.x86 import X86_INS_CALL
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32

        calls: dict[ptr_t, utils.signinfo] = { }
        md = Cs(CS_ARCH_X86, CS_MODE_64 if (X64DBGINFO.x64dbg) else CS_MODE_32)
        md.skipdata = True
        for insn in md.disasm(buffer, base):
            # Check for CALL instruction with absolute address operand
            if (insn.id != X86_INS_CALL or insn.op_str[:2] != "0x"):
                continue
            addr = int(insn.op_str, 0)
            if base <= addr < base + len(buffer):
                calls[addr] = utils.signinfo()
        return calls