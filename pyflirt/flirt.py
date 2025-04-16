#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from x64dbgpy3.x64dbgpyt3 import *

from capstone import *
from capstone.x86 import *


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
        fn: dict[ptr_t, utils.signinfo] = { }
        md = Cs(CS_ARCH_X86, CS_MODE_64 if (X64DBGINFO.x64dbg) else CS_MODE_32)
        md.skipdata = True
        for insn in md.disasm(buffer, base):
            if (insn.id != X86_INS_CALL or insn.op_str[:2] != "0x"):
                continue
            target = int(insn.op_str, 0)
            # normal absolute call, no cross-memory block
            if (target >= base and target < base + len(buffer)):
                fn[target] = utils.signinfo()
        return fn


class matcher:

    from .signature import idasig

    def __readbyte(self, offset:size_t):
        offset -= self.base
        return self.binary[offset]

    def __readint32(self, offset:size_t):
        from struct import unpack

        offset -= self.base
        return unpack("<i", self.binary[offset:offset+4])[0]

    # direct port from flair tools flair/crc16.cpp
    def __crc16(self, addr:ptr_t, length:size_t):
        if length == 0:
            return 0
        crc = 0xffff
        for i in range(length):
            data = self.__readbyte(addr + i)
            for j in range(8):
                if (crc ^ data) & 1:
                    crc = (crc >> 1) ^ 0x8408
                else:
                    crc >>= 1
                data >>= 1
        crc = ~crc
        data = crc
        crc = (crc << 8) | ((data >> 8) & 0xff)
        return crc & 0xffff

    def __pattern_match(self, node:dict, offset:size_t):
        for i in range(node['length']):
            if not node['variant_bool_array'][i]:
                if node['pattern_bytes'][i] != self.__readbyte(offset + i):
                    return False
        return True

    def __node_match(self, node:dict, addr:ptr_t, offset:size_t=0):
        if (self.__pattern_match(node, addr + offset)):
            if (node['child_list']):
                for child in node['child_list']:
                    if (self.__node_match(child, addr, offset + node['length'])):
                        return True 
            elif (node['module_list']):
                for module in node['module_list']:
                    if (self.__module_match(module, addr)):
                        return True
        return False

    def __module_match(self, module:dict, addr:ptr_t):
        # check crc
        if module['crc16'] != self.__crc16(addr + 32, module['crc_length']):
            return False
        # check tail bytes
        for tail_byte in module.get('tail_bytes', []):
            if tail_byte['value'] != self.__readbyte(addr + 32 + module['crc_length'] + tail_byte['offset']):
                return False
        # check referenced function
        if ('referenced_functions' in module):
            for ref_function in module['referenced_functions']:
                # get addess for referenced function
                ref_offset = addr + ref_function['offset']
                call_opcode = self.__readbyte(ref_offset - 1)
                # relative or absolute call? still unsure if absolute is used
                if call_opcode == 0xe8:
                    ref_address = self.__readint32(ref_offset) + ref_offset + 4
                elif call_opcode == 0xff:
                    ref_address = self.__readint32(ref_offset)
                else:
                    return False
                # check if referenced function have name
                if (self.calls()[ref_address].name):
                    if ref_function['name'] != self.calls()[ref_address].name:
                        return False
                else:
                    self.__referenced_calls[addr] = self.calls()[addr]
                    return False
            # passes referenced fuction checking, remove referenced function address from dictionary
            self.__referenced_calls.pop(addr, None)

        for public_function in module['public_functions']:
            if public_function['name'] != '?':
                if public_function['offset'] == 0:
                    self.calls()[addr].name = public_function['name']
                else:
                    self.calls()[addr + public_function['offset']].name = public_function['name']
        return True


    def __init__(self, addr:ptr_t, size:size_t):
        self.base = addr
        self.binary = utils.read(addr, size)
        self.__calls = utils.exec_formblock(self.binary, self.base)
        self.__referenced_calls: dict[ptr_t, utils.signinfo] = { }

    def calls(self):
        return self.__calls

    class matchinfo:
        addr: ptr_t
        name: str

    def match(self, flirt:idasig):
        fn:list[matcher.matchinfo] = []
        for target in self.calls():
            for child in flirt.tree['child_list']:
                if (self.__node_match(child, target)):
                    info = matcher.matchinfo()
                    info.addr = target
                    info.name = self.calls()[target].name
                    fn.append(info)
                    break

        # check for skipped referenced function
        while True:
            temp = self.__referenced_calls
            for target in self.__referenced_calls:
                for child_node in flirt.tree["child_list"]:
                    if self.__node_match(child_node, target):
                        info = matcher.matchinfo()
                        info.addr = target
                        info.name = self.calls()[target].name
                        fn.append(info)
                        break
            # stop if does not found any referenced function
            if not self.__referenced_calls or temp == self.__referenced_calls:
                break

        return fn