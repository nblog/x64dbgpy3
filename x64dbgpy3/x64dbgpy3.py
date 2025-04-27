#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .x64dbgutil import *
from .x64dbgreq import *


''' HTTP REQUEST '''
X64DBGCALL = RequestJsonRpc("http://" + ':'.join(get_debugger_host()))


''' X64DBG INFORMATION '''
class XDBGINFO(BaseModel):
    plugin: str
    x64dbg: bool
    x64dbg_hwnd: ptr_t
    x64dbg_dir: str
X64DBGINFO = XDBGINFO(**X64DBGCALL.x64dbg_info())


class dbgLogging:
    '''  '''

    @staticmethod
    def logclear() -> None:
        return X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgLogging), [  ] )

    @staticmethod
    def logputs(*values) -> None:
        return X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgLogging), [ ''.join([str(i) for i in values]) ] )

    @staticmethod
    def logprint(*values) -> None:
        return X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgLogging), [ ''.join([str(i) for i in values]) ] )

class dbgMisc:
    '''  '''

    class DBGWATCHINFO(BaseModel):
        class WATCHVARTYPE(IntEnum):
            UINT, INT, FLOAT, ASCII, UNICODE, INVALID = map(int, range(0, 6))
            def __str__(self):
                return { 
                    0:"UINT", 
                    1:"INT", 
                    2:"FLOAT", 
                    3:"ASCII", 
                    4:"UNICODE", 
                    5:"INVALID" 
                }.get(self.value, "UNKNOWN").lower()
        class WATCHDOGMODE(IntEnum):
            DISABLED, ISTRUE, ISFALSE, CHANGED, UNCHANGED = map(int, range(0, 5))
            def __str__(self):
                return { 
                    0:"DISABLED", 
                    1:"ISTRUE", 
                    2:"ISFALSE", 
                    3:"CHANGED", 
                    4:"UNCHANGED" 
                }.get(self.value, "UNKNOWN").lower()
        WatchName:str
        Expression:str
        window:int
        id:int
        varType:WATCHVARTYPE
        watchdogMode:WATCHDOGMODE
        value:ptr_t
        watchdogTriggered:bool

    @staticmethod
    def Sleep(s:int) -> None:
        from time import sleep; sleep(s - 1)
        return X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgMisc), [ 1 ] )

    @staticmethod
    def GetLabelAt(addr:ptr_t) -> str:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgMisc), [ addr ] )
        return str( res )

    @staticmethod
    def GetCommentAt(addr:ptr_t) -> str:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgMisc), [ addr ] )
        return str( res )

    @staticmethod
    def GetStringAt(addr:ptr_t) -> str:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgMisc), [ addr ] )
        return str( res )

    @staticmethod
    def GetWatchList() -> list[DBGWATCHINFO]:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgMisc), [  ] )
        if (not res): return [ ]
        return [ dbgMisc.DBGWATCHINFO(**i) for i in res ]

    @staticmethod
    def ParseExpression(expr:str) -> ptr_t:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgMisc), [ expr ] )
        return ptr_t( res )

    @staticmethod
    def ResolveLabel(label:str) -> ptr_t:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgMisc), [ label ] )
        return ptr_t( res )

    @staticmethod
    def RemoteGetProcAddress(module:str, api:str) -> ptr_t:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgMisc), [ module, api ] )
        return ptr_t( res )

class dbgGui:
    '''  '''

    class DBGGUIWINDOW(IntEnum):
        DisassemblyWindow, \
        DumpWindow, \
        StackWindow, \
        GraphWindow, \
        MemMapWindow, \
        SymModWindow, \
        ThreadsWindow, = map(int, range(0, 7))
        def __str__(self):
            return { 
                0:"DISASSEMBLY", 
                1:"DUMP", 
                2:"STACK", 
                3:"GRAPH", 
                4:"MEMMAP", 
                5:"SYMMOD", 
                6:"THREADS" 
            }.get(self.value, "UNKNOWN").lower()

    @staticmethod
    def FocusView(win:DBGGUIWINDOW) -> None:
        return X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgGui), [ win.value ] )

    @staticmethod
    def Refresh() -> None:
        return X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgGui), [  ] )

    @staticmethod
    def Message(message:str) -> None:
        return X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgGui), [ message ] )

    @staticmethod
    def MessageYesNo(message:str) -> bool:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgGui), [ message ] )
        return bool( res )

    @staticmethod
    def SelectionSet(win:DBGGUIWINDOW, start:ptr_t, end:ptr_t) -> bool:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgGui), [ win.value, start, end ] )
        return bool( res )

    @staticmethod
    def SelectionGet(win:DBGGUIWINDOW) -> tuple[ptr_t, ptr_t]:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgGui), [ win.value ] )
        return ( ptr_t(res[0]), ptr_t(res[1]) )

class dbgPattern:
    '''  '''

    @staticmethod
    def FindPattern(addr:ptr_t, pattern:str) -> None:
        return X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgPattern), [ addr, pattern ] )

class dbgAssembler:
    '''  '''

    @staticmethod
    def Assemble(addr:ptr_t, instruction:str) -> bool:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgAssembler), [ addr, instruction ] )
        return bool( res )

    @staticmethod
    def AssembleEx(addr:ptr_t, instruction:str, fillnop:bool=True) -> str:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgAssembler), [ addr, instruction, fillnop ] )
        return str( res )

    class DBGDISASMINFO(BaseModel):
        class INSTRUCTIONTYPE(IntFlag):
            VALUE, MEMORY, ADDRESS = 1, 2, 4
        type:INSTRUCTIONTYPE
        addr:ptr_t
        branch:bool
        call:bool
        size:int
        instruction:str

    @staticmethod
    def DisasmFast(addr:ptr_t) -> DBGDISASMINFO:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgAssembler), [ addr ] )
        return dbgAssembler.DBGDISASMINFO(**res)

class dbgSymbol:
    '''  '''

    class DBGSYMBOLINFO2(BaseModel):
        class DBGSYMBOLTYPE(IntEnum):
            FUNCTION, IMPORT, EXPORT = 0, 1, 2
            def __str__(self):
                return { 
                    0:"FUN/SYM", 
                    1:"IMPORT", 
                    2:"EXPORT",
                }.get(self.value, "UNKNOWN").lower()
        mod:str
        rva:ptr_t
        name:str
        manual:bool
        type:DBGSYMBOLTYPE

    class DBGSYMBOLINFO(BaseModel):
        class DBGSYMBOLTYPE(IntEnum):
            sym_import, sym_export, sym_symbol = 0, 1, 2
        addr:ptr_t
        decoratedSymbol:str
        undecoratedSymbol:str
        type:DBGSYMBOLTYPE
        freeDecorated:bool
        freeUndecorated:bool
        ordinal:int

    @staticmethod
    def GetSymbolList() -> list[DBGSYMBOLINFO2]:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgSymbol), [  ] )
        if (not res): return [ ]
        return [ dbgSymbol.DBGSYMBOLINFO2(**i) for i in res ]

    @staticmethod
    def Get(addr:ptr_t) -> DBGSYMBOLINFO:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgSymbol), [ addr ] )
        return dbgSymbol.DBGSYMBOLINFO(**res)

class dbgBookmark:
    '''  '''

    class DBGBOOKMARKINFO(BaseModel):
        mod:str
        rva:ptr_t
        manual:bool

    @staticmethod
    def GetBookmarkList() -> list[DBGBOOKMARKINFO]:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgBookmark), [  ] )
        if (not res): return [ ]
        return [ dbgBookmark.DBGBOOKMARKINFO(**i) for i in res ]

    @staticmethod
    def Get(addr:ptr_t) -> DBGBOOKMARKINFO:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgBookmark), [ addr ] )
        return dbgBookmark.DBGBOOKMARKINFO(**res)

    @staticmethod
    def Set(addr:ptr_t, manual:bool=False) -> bool:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgBookmark), [ addr, manual ] )
        return bool( res )

    @staticmethod
    def Del(addr:ptr_t) -> bool:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgBookmark), [ addr ] )
        return bool( res )

class dbgComment:
    '''  '''

    class DBGCOMMENTINFO(BaseModel):
        mod:str
        rva:ptr_t
        text:str
        manual:bool

    @staticmethod
    def GetCommentList() -> list[DBGCOMMENTINFO]:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgComment), [  ] )
        if (not res): return [ ]
        return [ dbgComment.DBGCOMMENTINFO(**i) for i in res ]

    @staticmethod
    def Get(addr:ptr_t) -> DBGCOMMENTINFO:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgComment), [ addr ] )
        return dbgComment.DBGCOMMENTINFO(**res)

    @staticmethod
    def Set(addr:ptr_t, text:str, manual:bool=False) -> bool:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgComment), [ addr, text, manual ] )
        return bool( res )

    @staticmethod
    def Del(addr:ptr_t) -> bool:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgComment), [ addr ] )
        return bool( res )

class dbgLabel:
    '''  '''

    class DBGLABELINFO(BaseModel):
        mod:str
        rva:ptr_t
        text:str
        manual:bool

    @staticmethod
    def IsTemporary(addr:ptr_t) -> bool:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgLabel), [ addr ] )
        return bool( res )

    @staticmethod
    def FromString(label:str) -> ptr_t:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgLabel), [ label ] )
        return ptr_t( res )

    @staticmethod
    def GetLabelList() -> list[DBGLABELINFO]:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgLabel), [  ] )
        if (not res): return [ ]
        return [ dbgLabel.DBGLABELINFO(**i) for i in res ]

    @staticmethod
    def Get(addr:ptr_t) -> DBGLABELINFO:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgLabel), [ addr ] )
        return dbgLabel.DBGLABELINFO(**res)

    @staticmethod
    def Set(addr:ptr_t, label:str, manual:bool=False, temporary:bool=False) -> bool:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgLabel), [ addr, label, manual, temporary ] )
        return bool( res )

    @staticmethod
    def Del(addr:ptr_t) -> bool:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgLabel), [ addr ] )
        return bool( res )

class dbgFunction:
    '''  '''

    class DBGFUNCTIONINFO(BaseModel):
        mod:str
        rvaStart:ptr_t
        rvaEnd:ptr_t
        manual:bool
        instructioncount:size_t

    @staticmethod
    def Overlaps():
        raise NotImplementedError

    @staticmethod
    def GetFunctionList() -> list[DBGFUNCTIONINFO]:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgFunction), [  ] )
        if (not res): return [ ]
        return [ dbgFunction.DBGFUNCTIONINFO(**i) for i in res ]

    @staticmethod
    def Get(addr:ptr_t) -> DBGFUNCTIONINFO:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgFunction), [ addr ] )
        return dbgFunction.DBGFUNCTIONINFO(**res)

    @staticmethod
    def Add(start:ptr_t, end:ptr_t, manual:bool=False, instructionCount:size_t=0) -> bool:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgFunction), [ start, end, manual, instructionCount ] )
        return bool( res )

    @staticmethod
    def Del(addr:ptr_t) -> bool:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgFunction), [ addr ] )
        return bool( res )

class dbgArgument:
    '''  '''

    class DBGARGUMENTINFO(BaseModel):
        mod:str
        rvaStart:ptr_t
        rvaEnd:ptr_t
        manual:bool
        instructioncount:size_t

    @staticmethod
    def Overlaps():
        raise NotImplementedError

    @staticmethod
    def GetArgumentList() -> list[DBGARGUMENTINFO]:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgArgument), [  ] )
        if (not res): return [ ]
        return [ dbgArgument.DBGARGUMENTINFO(**i) for i in res ]

    @staticmethod
    def Get(addr:ptr_t) -> DBGARGUMENTINFO:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgArgument), [ addr ] )
        return dbgArgument.DBGARGUMENTINFO(**res)

    @staticmethod
    def Add(start:ptr_t, end:ptr_t, manual:bool=False, instructionCount:size_t=0) -> bool:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgArgument), [ start, end, manual, instructionCount ] )
        return bool( res )

    @staticmethod
    def Del(addr:ptr_t) -> bool:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgArgument), [ addr ] )
        return bool( res )

class dbgXref:
    '''  '''

    class DBGXREFINFO(BaseModel):
        class DBGXREFRECORD(BaseModel):
            class DBGXREFTYPE(IntEnum):
                XREF_NONE, XREF_DATA, XREF_JMP, XREF_CALL = 0, 1, 2, 3
            addr:ptr_t
            type:int
        refcount:size_t
        xrefs:list[DBGXREFRECORD]

    @staticmethod
    def Get(addr:ptr_t) -> DBGXREFINFO:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgXref), [ addr ] )
        return dbgXref.DBGXREFINFO(**res)

    @staticmethod
    def Add(addr:ptr_t, from_:ptr_t) -> bool:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgXref), [ addr, from_ ] )
        return bool( res )

    @staticmethod
    def DelAll(addr:ptr_t) -> bool:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgXref), [ addr ] )
        return bool( res )

    @staticmethod
    def GetCountAt(addr:ptr_t) -> size_t:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgXref), [ addr ] )
        return int( res )

    @staticmethod
    def GetTypeAt(addr:ptr_t) -> DBGXREFINFO.DBGXREFRECORD.DBGXREFTYPE:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgXref), [ addr ] )
        return dbgXref.DBGXREFINFO.DBGXREFRECORD.DBGXREFTYPE(res)

class dbgScript:
    '''  '''

    @staticmethod
    def Load(filename:str) -> None:
        return X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgScript), [ filename ] )

    @staticmethod
    def Unload() -> None:
        return X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgScript), [  ] )

    @staticmethod
    def Run(destline:int) -> None:
        return X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgScript), [ destline ] )

    @staticmethod
    def Abort() -> None:
        return X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgScript), [  ] )

    @staticmethod
    def CmdExec(command:str) -> None:
        return X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgScript), [ command ] )

class dbgBreakpoint:
    '''  '''

    class DBGBREAKPOINTINFO(BaseModel):
        class BPXTYPE(IntFlag):
            bp_none, bp_normal, bp_hardware, bp_memory, bp_dll, bp_exception = \
                0, 1, 2, 4, 8, 16
            def __str__(self):
                return { 
                    0:"NONE", 
                    1:"NORMAL", 
                    2:"HARDWARE", 
                    4:"MEMORY", 
                    8:"DLL", 
                    16:"EXCEPTION" 
                }.get(self.value, "UNKNOWN").lower()
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
    def GetBreakpointList(bpxtype:DBGBREAKPOINTINFO.BPXTYPE=DBGBREAKPOINTINFO.BPXTYPE.bp_none) -> list[DBGBREAKPOINTINFO]:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgBreakpoint), [ bpxtype.value ] )
        if (not res): return [ ]
        return [ dbgBreakpoint.DBGBREAKPOINTINFO(**i) for i in res ]

    @staticmethod
    def SetBreakpoint(addr:ptr_t) -> bool:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgBreakpoint), [ addr ] )
        return bool( res )

    @staticmethod
    def DeleteBreakpoint(addr:ptr_t) -> bool:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgBreakpoint), [ addr ] )
        return bool( res )

    @staticmethod
    def DisableBreakpoint(addr:ptr_t) -> bool:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgBreakpoint), [ addr ] )
        return bool( res )

    class DBGHARDWARETYPE(IntEnum):
        HardwareAccess, \
        HardwareWrite, \
        HardwareExecute = 0, 1, 2
        def __str__(self):
            return { 
                0:"ACCESS", 
                1:"WRITE", 
                2:"EXECUTE" 
            }.get(self.value, "UNKNOWN").lower()

    @staticmethod
    def SetHardwareBreakpoint(addr:ptr_t, hard:DBGHARDWARETYPE) -> bool:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgBreakpoint), [ addr, hard.value ] )
        return bool( res )

    @staticmethod
    def DeleteHardwareBreakpoint(addr:ptr_t) -> bool:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgBreakpoint), [ addr ] )
        return bool( res )

class dbgModule:
    '''  '''

    class DBGMODULEIMPORTINFO(BaseModel):
        iatRva:ptr_t
        iatVa:ptr_t
        ordinal:ptr_t
        name:str
        undecoratedName:str

    class DBGMODULEEXPORTINFO(BaseModel):
        ordinal:ptr_t
        rva:ptr_t
        va:ptr_t
        forwarded:bool
        forwardName:str
        name:str
        undecoratedName:str

    class DBGMODULESECTIONINFO(BaseModel):
        addr:ptr_t
        size:size_t
        name:str

    class DBGMODULEINFO(BaseModel):
        base:ptr_t
        size:size_t
        entry:ptr_t
        sectionCount:int
        name:str
        path:str

    @staticmethod
    def GetModuleList() -> list[DBGMODULEINFO]:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgModule), [  ] )
        return [ dbgModule.DBGMODULEINFO(**i) for i in res ]

    @staticmethod
    def GetMainModuleInfo() -> DBGMODULEINFO:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgModule), [  ] )
        return dbgModule.DBGMODULEINFO(**res)

    @staticmethod
    def InfoFromAddr(addr:ptr_t) -> DBGMODULEINFO:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgModule), [ addr ] )
        return dbgModule.DBGMODULEINFO(**res)

    @staticmethod
    def InfoFromName(name:str) -> DBGMODULEINFO:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgModule), [ name ] )
        return dbgModule.DBGMODULEINFO(**res)

    @staticmethod
    def GetMainModuleSectionList() -> list[DBGMODULESECTIONINFO]:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgModule), [  ] )
        if (not res): return [ ]
        return [ dbgModule.DBGMODULESECTIONINFO(**i) for i in res ]

    @staticmethod
    def SectionListFromAddr(addr:ptr_t) -> list[DBGMODULESECTIONINFO]:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgModule), [ addr ] )
        if (not res): return [ ]
        return [ dbgModule.DBGMODULESECTIONINFO(**i) for i in res ]

    @staticmethod
    def SectionListFromName(name:str) -> list[DBGMODULESECTIONINFO]:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgModule), [ name ] )
        if (not res): return [ ]
        return [ dbgModule.DBGMODULESECTIONINFO(**i) for i in res ]

    @staticmethod
    def GetExportsFromAddr(addr:ptr_t) -> list[DBGMODULEEXPORTINFO]:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgModule), [ addr ] )
        if (not res): return [ ]
        return [ dbgModule.DBGMODULEEXPORTINFO(**i) for i in res ]

    @staticmethod
    def GetImportsFromAddr(addr:ptr_t) -> list[DBGMODULEIMPORTINFO]:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgModule), [ addr ] )
        if (not res): return [ ]
        return [ dbgModule.DBGMODULEIMPORTINFO(**i) for i in res ]

class dbgThread:
    '''  '''

    class DBGTHREADALLINFO(BaseModel):
        class FILETIME(BaseModel):
            dwLowDateTime:int
            dwHighDateTime:int
            def __str__(self):
                filetime = (self.dwHighDateTime << 32) + self.dwLowDateTime
                # UTC
                return filetime_to_datetime(filetime).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        class DBGTHREADINFO(BaseModel):
            ThreadNumber:int
            Handle:ptr_t
            ThreadId:int
            ThreadStartAddress:ptr_t
            ThreadLocalBase:ptr_t
            threadName:str
        BasicInfo:DBGTHREADINFO
        ThreadCip:ptr_t
        SuspendCount:int
        Priority:int
        WaitReason:int
        LastError:int
        UserTime:FILETIME
        KernelTime:FILETIME
        CreationTime:FILETIME
        Cycles:int

    @staticmethod
    def GetThreadList() -> list[DBGTHREADALLINFO]:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgThread), [  ] )
        return [ dbgThread.DBGTHREADALLINFO(**i) for i in res ]

    @staticmethod
    def GetFirstThreadId() -> int:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgThread), [  ] )
        return int( res )

    @staticmethod
    def SetThreadName(threadid:int, name:str) -> bool:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgThread), [ threadid, name ] )
        return bool( res )

    @staticmethod
    def SetActiveThreadId(threadid:int) -> bool:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgThread), [ threadid ] )
        return bool( res )

    @staticmethod
    def SuspendThreadId(threadid:int) -> bool:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgThread), [ threadid ] )
        return bool( res )

    @staticmethod
    def ResumeThreadId(threadid:int) -> bool:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgThread), [ threadid ] )
        return bool( res )

    @staticmethod
    def KillThread(threadid:int, code:int=0) -> bool:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgThread), [ threadid, code ] )
        return bool( res )

    @staticmethod
    def CreateThread(entry:ptr_t, arg0:ptr_t=0) -> bool:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgThread), [ entry, arg0 ] )
        return bool( res )

class dbgProcess:
    '''  '''

    @staticmethod
    def ProcessId() -> int:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgProcess), [  ] )
        return int( res )

    @staticmethod
    def NativeHandle() -> ptr_t:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgProcess), [  ] )
        return ptr_t( res )

class dbgMemory:
    '''  '''

    class MEM_PROTECT(IntFlag):
        @staticmethod
        def str(v): return \
            ('r' if ( v & 2 | v & 4 | v & 0x20 ) else '-') + \
            ('w' if ( v & 4 | v & 8 | v & 0x40 | v & 0x80 ) else '-') + \
            ('x' if ( v & 0x10 | v & 0x20 | v & 0x40 | v & 0x80 ) else '-')

    class MEM_TYPE(IntEnum):
        @staticmethod
        def str(v): return \
            { 0x1000000:"IMG", 0x40000:"MAP", 0x20000:"PRV" }.get(v, "N/A")

    class DBGMEMMAPINFO(BaseModel):
        BaseAddress:ptr_t
        AllocationBase:ptr_t
        AllocationProtect:int
        RegionSize:size_t
        State:int 
        Protect:int
        Type:int
        info:str

    @staticmethod
    def MemMaps() -> list[DBGMEMMAPINFO]:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgMemory), [  ] )
        return [ dbgMemory.DBGMEMMAPINFO(**i) for i in res ]

    @staticmethod
    def ValidPtr(addr:ptr_t) -> bool:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgMemory), [ addr ] )
        return bool( res )

    @staticmethod
    def Free(addr:ptr_t) -> bool:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgMemory), [ addr ] )
        return bool( res )

    @staticmethod
    def Alloc(size:size_t, addr:ptr_t=0) -> ptr_t:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgMemory), [ size, addr ] )
        return ptr_t( res )

    @staticmethod
    def Base(addr:ptr_t, reserved:bool=False, cache:bool=True) -> ptr_t:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgMemory), [ addr, reserved, cache ] )
        return ptr_t( res )

    @staticmethod
    def Size(addr:ptr_t, reserved:bool=False, cache:bool=True) -> size_t:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgMemory), [ addr, reserved, cache ] )
        return size_t( res )

    @staticmethod
    def Write(addr:ptr_t, data:bytes) -> bool:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgMemory), [
            addr, RequestBuffer.serialize(data) ] )
        return bool( res )

    @staticmethod
    def Read(addr:ptr_t, size:size_t) -> bytes:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgMemory), [
            addr, size ] )
        return RequestBuffer.deserialize( res )

class dbgStack:
    '''  '''

    @staticmethod
    def Pop() -> ptr_t:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgStack), [ ] )
        return ptr_t( res )

    @staticmethod
    def Push(value:ptr_t) -> ptr_t:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgStack), [ value ] )
        return ptr_t( res )

class dbgRegister:
    '''  '''

    class DBGFLAGENUM(IntEnum):
        ''' FLAGS '''
        ZF, OF, CF, PF, SF, TF, AF, DF, IF = \
            0, 1, 2, 3, 4, 5, 6, 7, 8

    @staticmethod
    def GetFlag(flag:DBGFLAGENUM) -> ptr_t:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgRegister), [ flag.value ] )
        return ptr_t( res )

    @staticmethod
    def SetFlag(flag:DBGFLAGENUM, value:bool) -> bool:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgRegister), [ flag.value, value ] )
        return bool( res )

    class DBGREGISTERENUM_DEBUG:
        ''' DEBUG '''
        DR0, DR1, DR2, DR3, DR6, DR7 = \
            map(int, range(0, 6))

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

    class DBGREGISTERENUM(DBGREGISTERENUM_DEBUG, DBGREGISTERENUM_WIN32, DBGREGISTERENUM_WIN64, IntEnum):
        CIP, CSP, CAX, CBX, CCX, CDX, CDI, CSI, CBP, CFLAGS = \
            map(int, range(76, 86)) if (X64DBGINFO.x64dbg) else map(int, range(31, 41))

    @staticmethod
    def GetRegister(reg:DBGREGISTERENUM) -> ptr_t:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgRegister), [ reg ] )
        return ptr_t( res )

    @staticmethod
    def SetRegister(reg:DBGREGISTERENUM, value:ptr_t) -> bool:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgRegister), [ reg, value ] )
        return bool( res )

class dbgDebug:
    '''  '''

    @staticmethod
    def Stop() -> None:
        return X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgDebug), [  ] )

    @staticmethod
    def Run() -> None:
        return X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgDebug), [  ] )

    @staticmethod
    def Pause() -> None:
        return X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgDebug), [  ] )

    @staticmethod
    def StepInto() -> None:
        return X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgDebug), [  ] )

    @staticmethod
    def StepOver() -> None:
        return X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgDebug), [  ] )

    @staticmethod
    def StepOut() -> None:
        return X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgDebug), [  ] )

    @staticmethod
    def IsDebugging() -> bool:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgDebug), [  ] )
        return bool( res )

    @staticmethod
    def IsRunning() -> bool:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgDebug), [  ] )
        return bool( res )

    @staticmethod
    def RunCommand(cmd:str) -> bool:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgDebug), [ cmd ] )
        return bool( res )

    @staticmethod
    def RunCommandAsync(cmd:str) -> bool:
        res = X64DBGCALL.x64dbg_call( FUNCTION_NAME(dbgDebug), [ cmd ] )
        return bool( res )