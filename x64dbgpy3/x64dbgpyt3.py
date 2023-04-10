#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .x64dbgutil import *
from .x64dbgreq import *



''' HTTP REQ '''
import os
DEFAULT_PORT, DEFAULT_HOST = 27043, os.environ.get("REMOTEHOST", "localhost")
X64DBGREQ = reqJson( "http://{}:{}".format(DEFAULT_HOST, DEFAULT_PORT) )


''' X64DBG INFO '''
class XDBGINFO(DBGNS):
    ver:int
    x64dbg:bool
    dbgver:int
    dbgengine:int
    dbghwnd:ptr_t
X64DBGINFO = XDBGINFO(**X64DBGREQ.x64dbg_info())



class dbgLogging:
    '''  '''

    @staticmethod
    def logclear():
        X64DBGREQ.req_call( FUNCTION_NAME(dbgLogging), [  ], True )

    @staticmethod
    def logprint(text:str):
        X64DBGREQ.req_call( FUNCTION_NAME(dbgLogging), [ text ], True )

    @staticmethod
    def logputs(text:str):
        X64DBGREQ.req_call( FUNCTION_NAME(dbgLogging), [ text ], True )


class dbgMisc:
    '''  '''

    @staticmethod
    def IsDebugging():
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgMisc), [  ] )
        return bool(res)

    @staticmethod
    def IsRunning():
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgMisc), [  ] )
        return bool(res)

    @staticmethod
    def ParseExpression(expr:str):
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgMisc), [ expr ] )
        return ptr_t(res)

    @staticmethod
    def ResolveLabel(label:str):
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgMisc), [ label ] )
        return ptr_t(res)

    @staticmethod
    def RemoteGetProcAddress(module:str, api:str):
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgMisc), [ module, api ] )
        return ptr_t(res)


class dbgGui:
    '''  '''

    class DBGGUIWINDOW:
        DisassemblyWindow, \
        DumpWindow, \
        StackWindow, \
        GraphWindow, \
        MemMapWindow, \
        SymModWindow = 0, 1, 2, 3, 4, 5

    @staticmethod
    def Refresh():
        X64DBGREQ.req_call( FUNCTION_NAME(dbgGui), [  ], True )

    @staticmethod
    def Message(message:str):
        X64DBGREQ.req_call( FUNCTION_NAME(dbgGui), [ message ], True )

    @staticmethod
    def FocusView(win:DBGGUIWINDOW):
        X64DBGREQ.req_call( FUNCTION_NAME(dbgGui), [ win ], True )

    @staticmethod
    def SelectionSet(win:DBGGUIWINDOW, start:ptr_t, end:ptr_t):
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgGui), [ win, start, end ] )
        return bool( res )

    @staticmethod
    def SelectionGet(win:DBGGUIWINDOW):
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgGui), [ win ] )
        return ( ptr_t(res[0]), ptr_t(res[1]) )



class dbgPattern:
    '''  '''

    @staticmethod
    def FindPattern(addr:ptr_t, pattern:str):
        X64DBGREQ.req_call( FUNCTION_NAME(dbgPattern), [ addr, pattern ], True )



class dbgAssembler:
    '''  '''

    @staticmethod
    def Assemble(addr:ptr_t, instruction:str):
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgAssembler), [ addr, instruction ] )
        return bool( res )

    class DBGDISASMINFO(DBGNS):
        class INSTRUCTIONTYPE:
            VALUE, MEMORY, ADDRESS = 1, 2, 4
        type:INSTRUCTIONTYPE
        addr:ptr_t
        branch:bool
        call:bool
        size:int
        instruction:str

    @staticmethod
    def DisasmFast(addr:ptr_t):
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgAssembler), [ addr ] )
        return dbgAssembler.DBGDISASMINFO(**res)


class dbgSymbol:
    '''  '''

    class DBGSYMBOLINFO(DBGNS):
        class DBGSYMBOLTYPE:
            FUNCTION, IMPORT, EXPORT = 0, 1, 2
        mod:str
        rva:ptr_t
        name:str
        manual:bool
        type:DBGSYMBOLTYPE

    @staticmethod
    def GetSymbolList():
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgSymbol), [  ] )
        if (not res): return [ ]
        return [ dbgSymbol.DBGSYMBOLINFO(**i) for i in res ]

class dbgBookmark:
    '''  '''

    class DBGBOOKMARKINFO(DBGNS):
        mod:str
        rva:ptr_t
        manual:bool

    @staticmethod
    def GetBookmarkList():
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgBookmark), [  ] )
        if (not res): return [ ]
        return [ dbgBookmark.DBGBOOKMARKINFO(**i) for i in res ]

    @staticmethod
    def Set():
        raise NotImplementedError

    @staticmethod
    def Get():
        raise NotImplementedError

    @staticmethod
    def Del():
        raise NotImplementedError

class dbgComment:
    '''  '''

    class DBGCOMMENTINFO(DBGNS):
        mod:str
        rva:ptr_t
        text:str
        manual:bool

    @staticmethod
    def GetCommentList():
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgComment), [  ] )
        if (not res): return [ ]
        return [ dbgComment.DBGCOMMENTINFO(**i) for i in res ]

    @staticmethod
    def Set():
        raise NotImplementedError

    @staticmethod
    def Get():
        raise NotImplementedError

    @staticmethod
    def Del():
        raise NotImplementedError

class dbgLabel:
    '''  '''

    class DBGLABELINFO(DBGNS):
        mod:str
        rva:ptr_t
        text:str
        manual:bool

    @staticmethod
    def IsTemporary():
        raise NotImplementedError

    @staticmethod
    def FromString():
        raise NotImplementedError

    @staticmethod
    def GetLabelList():
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgLabel), [  ] )
        if (not res): return [ ]
        return [ dbgLabel.DBGLABELINFO(**i) for i in res ]

    @staticmethod
    def Set():
        raise NotImplementedError

    @staticmethod
    def Get():
        raise NotImplementedError

    @staticmethod
    def Del():
        raise NotImplementedError

class dbgFunction:
    '''  '''

    class DBGFUNCTIONINFO(DBGNS):
        mod:str
        rvaStart:ptr_t
        rvaEnd:str
        manual:bool
        instructioncount:ptr_t

    @staticmethod
    def Overlaps():
        raise NotImplementedError

    @staticmethod
    def GetFunctionList():
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgFunction), [  ] )
        if (not res): return [ ]
        return [ dbgFunction.DBGFUNCTIONINFO(**i) for i in res ]

    @staticmethod
    def Set():
        raise NotImplementedError

    @staticmethod
    def Get():
        raise NotImplementedError

    @staticmethod
    def Del():
        raise NotImplementedError

class dbgArgument:
    '''  '''

    class DBGARGUMENTINFO(DBGNS):
        mod:str
        rvaStart:ptr_t
        rvaEnd:str
        manual:bool
        instructioncount:ptr_t

    @staticmethod
    def Overlaps():
        raise NotImplementedError

    @staticmethod
    def GetArgumentList():
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgArgument), [  ] )
        if (not res): return [ ]
        return [ dbgArgument.DBGARGUMENTINFO(**i) for i in res ]

    @staticmethod
    def Add():
        raise NotImplementedError

    @staticmethod
    def Get():
        raise NotImplementedError

    @staticmethod
    def Del():
        raise NotImplementedError


class dbgModule:
    '''  '''

    class DBGMODULEIMPORTINFO(DBGNS):
        iatRva:ptr_t
        iatVa:ptr_t
        ordinal:ptr_t
        name:str
        undecoratedName:str

    class DBGMODULEEXPORTINFO(DBGNS):
        ordinal:ptr_t
        rva:ptr_t
        va:ptr_t
        forwarded:bool
        forwardName:str
        name:str
        undecoratedName:str

    class DBGMODULESECTIONINFO(DBGNS):
        addr:ptr_t
        size:size_t
        name:str

    class DBGMODULEINFO(DBGNS):
        base:ptr_t
        size:size_t
        entry:ptr_t
        sectionCount:int
        name:str
        path:str

    @staticmethod
    def GetModuleList():
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgModule), [  ] )
        return [ dbgModule.DBGMODULEINFO(**i) for i in res ]

    @staticmethod
    def GetMainModuleInfo():
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgModule), [  ] )
        return dbgModule.DBGMODULEINFO(**res)

    @staticmethod
    def InfoFromAddr(addr:ptr_t):
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgModule), [ addr ] )
        return dbgModule.DBGMODULEINFO(**res)

    @staticmethod
    def InfoFromName(name:ptr_t):
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgModule), [ name ] )
        return dbgModule.DBGMODULEINFO(**res)

    @staticmethod
    def GetMainModuleSectionList():
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgModule), [  ] )
        if (not res): return [ ]
        return [ dbgModule.DBGMODULESECTIONINFO(**i) for i in res ]

    @staticmethod
    def SectionListFromAddr(addr:ptr_t):
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgModule), [ addr ] )
        if (not res): return [ ]
        return [ dbgModule.DBGMODULESECTIONINFO(**i) for i in res ]

    @staticmethod
    def SectionListFromName(name:ptr_t):
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgModule), [ name ] )
        if (not res): return [ ]
        return [ dbgModule.DBGMODULESECTIONINFO(**i) for i in res ]

    @staticmethod
    def GetExportsFromAddr(addr:ptr_t):
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgModule), [ addr ] )
        if (not res): return [ ]
        return [ dbgModule.DBGMODULEEXPORTINFO(**i) for i in res ]

    @staticmethod
    def GetImportsFromAddr(addr:ptr_t):
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgModule), [ addr ] )
        if (not res): return [ ]
        return [ dbgModule.DBGMODULEIMPORTINFO(**i) for i in res ]

class dbgThread:
    '''  '''

    class DBGTHREADINFO(DBGNS):
        ThreadNumber:int
        ThreadId:int
        ThreadStartAddress:ptr_t
        ThreadLocalBase:ptr_t
        threadName:str
        ThreadCip:ptr_t
        SuspendCount:int

    @staticmethod
    def GetThreadList():
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgThread), [  ] )
        return [ dbgThread.DBGTHREADINFO(**i) for i in res ]

    @staticmethod
    def GetFirstThreadId():
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgThread), [  ] )
        return int(res)

    @staticmethod
    def GetActiveThreadId():
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgThread), [  ] )
        return int(res)

    @staticmethod
    def SetActiveThreadId(threadid:int):
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgThread), [ threadid ] )
        return bool(res)

    @staticmethod
    def SuspendThreadId(threadid:int):
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgThread), [ threadid ] )
        return bool(res)

    @staticmethod
    def ResumeThreadId(threadid:int):
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgThread), [ threadid ] )
        return bool(res)

    @staticmethod
    def KillThread(threadid:int, code:int=0):
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgThread), [ threadid, code ] )
        return bool(res)

    @staticmethod
    def CreateThread(entry:ptr_t, arg0:ptr_t=0):
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgThread), [ entry, arg0 ] )
        return bool(res)

class dbgProcess:
    '''  '''

    @staticmethod
    def ProcessId():
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgProcess), [  ] )
        return int(res)

    @staticmethod
    def NativeHandle():
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgProcess), [  ] )
        return ptr_t(res)


class dbgMemory:
    '''  '''

    class MEM_TYPE:
        @staticmethod
        def str(v): 
            return { 0x1000000:"IMG", 0x40000:"MAP", 0x20000:"PRV" }[v]

    class MEM_PROTECT:
        @staticmethod
        def str(v): return \
            ('r' if ( v & 2 | v & 4 | v & 0x20 ) else '-') + \
            ('w' if ( v & 4 | v & 8 | v & 0x40 | v & 0x80 ) else '-') + \
            ('x' if ( v & 0x10 | v & 0x20 | v & 0x40 | v & 0x80 ) else '-')

    class DBGMEMMAPINFO(DBGNS):
        BaseAddress:ptr_t
        AllocationBase:ptr_t
        AllocationProtect:int
        RegionSize:size_t
        State:int 
        Protect:int
        Type:int
        info:str

    @staticmethod
    def MemMaps():
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgMemory), [  ] )
        return [ dbgMemory.DBGMEMMAPINFO(**i) for i in res ]

    @staticmethod
    def ValidPtr(addr:ptr_t):
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgMemory), [ addr ] )
        return bool(res)

    @staticmethod
    def Read(addr:ptr_t, size:size_t):
        ''' slice '''
        it = [4096] * int(size / 4096)
        if ( size % 4096 ): it.append( size % 4096 )

        rv, offset = b'', int(0)
        for length in it:
            res = X64DBGREQ.req_call( FUNCTION_NAME(dbgMemory), [ 
                addr+offset, length ] )
            rv += reqBuffer.deserialize(res)
            offset += length
        return rv

    @staticmethod
    def Write(addr:ptr_t, data:bytes):
        size, offset = len(data), int(0)

        ''' slice '''
        it = [4096] * int(size / 4096)
        if ( size % 4096 ): it.append( size % 4096 )

        for length in it:
            res = X64DBGREQ.req_call( FUNCTION_NAME(dbgMemory), [ \
                addr, reqBuffer.serialize(data[offset:offset+length]) ] )
            if (not bool(res)): return False
            offset += length
        return True

    @staticmethod
    def Free(addr:ptr_t):
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgMemory), [ addr ] )
        return bool( res )

    @staticmethod
    def Alloc(size:size_t, addr:ptr_t=0):
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgMemory), [ addr, size ] )
        return ptr_t( res )

    @staticmethod
    def Base(addr:ptr_t, reserved:bool=False, cache:bool=True):
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgMemory), [ addr, reserved, cache ] )
        return ptr_t( res )

    @staticmethod
    def Size(addr:ptr_t, reserved:bool=False, cache:bool=True):
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgMemory), [ addr, reserved, cache ] )
        return size_t( res )

class dbgStack:
    '''  '''

    @staticmethod
    def Pop():
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgStack), [ ] )
        return ptr_t( res )

    @staticmethod
    def Push(value:ptr_t):
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgStack), [ value ] )
        return ptr_t( res )

class dbgRegister:
    '''  '''

    class DBGFLAGENUM:
        ZF, OF, CF, PF, SF, TF, AF, DF, IF = \
            0, 1, 2, 3, 4, 5, 6, 7, 8

    @staticmethod
    def GetFlag(flag:DBGFLAGENUM):
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgRegister), [ flag ] )
        return ptr_t( res )

    @staticmethod
    def SetFlag(flag:DBGFLAGENUM, value:ptr_t):
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgRegister), [ flag, value ] )
        return ptr_t( res )


    class DBGREGISTERENUM_WIN32:
        ''' WIN32 '''
        EAX, AX, AH, AL, \
        EBX, BX, BH, BL, \
        ECX, CX, CH, CL, \
        EDX, DX, DH, DL, \
        EDI, DI, ESI, SI, EBP, BP, ESP, SP, \
        EIP = \
            map(int, range(6, 31))

    class DBGREGISTERENUM_WIN64:
        ''' WIN64 '''
        RAX, RBX, RCX, RDX, RSI, SIL, RDI, DIL, RBP, BPL, RSP, SPL, RIP, \
        R8, R8D, R8W, R8B, R9, R9D, R9W, R9B, R10, R10D, R10W, R10B, R11, \
        R11D, R11W, R11B, R12, R12D, R12W, R12B, R13, R13D, R13W, R13B, \
        R14, R14D, R14W, R14B, R15, R15D, R15W, R15B = \
            map(int, range(31, 76))

    class DBGREGISTERENUM(DBGREGISTERENUM_WIN32, DBGREGISTERENUM_WIN64):
        DR0, DR1, DR2, DR3, DR6, DR7 = \
            map(int, range(0, 6))

        CIP, CSP, CAX, CBX, CCX, CDX, CDI, CSI, CBP, CFLAGS = \
            map(int, range(76, 86)) if (X64DBGINFO.x64dbg) else map(int, range(31, 41))

    @staticmethod
    def GetRegister(reg:DBGREGISTERENUM):
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgRegister), [ reg ] )
        return ptr_t( res )

    @staticmethod
    def SetRegister(reg:DBGREGISTERENUM, value:ptr_t):
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgRegister), [ reg, value ] )
        return ptr_t( res )


class dbgDebug:
    '''  '''

    @staticmethod
    def Stop():
        X64DBGREQ.req_call( FUNCTION_NAME(dbgDebug), [  ], True )

    @staticmethod
    def Run():
        X64DBGREQ.req_call( FUNCTION_NAME(dbgDebug), [  ], True )

    @staticmethod
    def StepIn():
        X64DBGREQ.req_call( FUNCTION_NAME(dbgDebug), [  ], True )

    @staticmethod
    def StepOver():
        X64DBGREQ.req_call( FUNCTION_NAME(dbgDebug), [  ], True )

    @staticmethod
    def StepOut():
        X64DBGREQ.req_call( FUNCTION_NAME(dbgDebug), [  ], True )


    class DBGBREAKPOINTINFO(DBGNS):
        class BPXTYPE:
            bp_none, bp_normal, bp_hardware = 0, 1, 2
        type:BPXTYPE
        addr:ptr_t
        enabled:bool
        singleshoot:bool
        active:bool
        name:str
        mod:str
        hitCount:int
        breakCondition:str
        logCondition:str
        commandCondition:str
        logText:str
        commandText:str

    @staticmethod
    def GetBreakpointList(bpxtype:DBGBREAKPOINTINFO.BPXTYPE=DBGBREAKPOINTINFO.BPXTYPE.bp_none):
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgDebug), [ bpxtype ] )
        if (not res): return [ ]
        return [ dbgDebug.DBGBREAKPOINTINFO(**i) for i in res ]

    @staticmethod
    def SetBreakpoint(addr:ptr_t):
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgDebug), [ addr ] )
        return bool(res)

    @staticmethod
    def DeleteBreakpoint(addr:ptr_t):
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgDebug), [ addr ] )
        return bool(res)

    @staticmethod
    def DisableBreakpoint(addr:ptr_t):
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgDebug), [ addr ] )
        return bool(res)

    class DBGHARDWARETYPE:
        HardwareAccess, \
        HardwareWrite, \
        HardwareExecute = 0, 1, 2

    @staticmethod
    def SetHardwareBreakpoint(addr:ptr_t, hard:DBGHARDWARETYPE):
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgDebug), [ addr, hard ] )
        return bool(res)

    @staticmethod
    def DeleteHardwareBreakpoint(addr:ptr_t):
        res = X64DBGREQ.req_call( FUNCTION_NAME(dbgDebug), [ addr ] )
        return bool(res)