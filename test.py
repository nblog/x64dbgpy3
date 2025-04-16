#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from x64dbgpy3.x64dbgpyt3 import *


dbgLogging.logclear()
dbgLogging.logputs("hello python3")
dbgLogging.logprint("hello", " ", "python3\n")


if (not dbgMisc.IsDebugging()):
    dbgGui.Message( "please start debugging" ), exit(0)


for bp in dbgDebug.GetBreakpointList():
    descriptor = []
    if (bp.breakCondition):
        descriptor.append( "breakif({})".format(bp.breakCondition) )
    if (bp.logText):
        descriptor.append(
            "logif({}, \"{}\")".format(bp.logCondition, bp.logText) \
                if (bp.logCondition) else "log(\"{}\")".format(bp.logText)
        )
    if (bp.commandText):
        descriptor.append(
            "cmdif({}, \"{}\")".format(bp.commandCondition, bp.commandText) \
                if (bp.commandCondition) else "cmd(\"{}\")".format(bp.commandText)
        )

    print( "bp: {}  {:#x}  {}  {}  {}  {}".format(
        ( "soft" if (1 == bp.type) else ( "hard" if (2 == bp.type) else "none?" ) ),
        bp.addr, bp.mod, 
        ( "disable" if not bp.enabled else ( "enable" if not bp.singleshoot else "once" ) ),
        bp.hitCount,
        ', '.join(descriptor) ) )

for book in dbgBookmark.GetBookmarkList():
    print( "book: {}+{:#x}".format( book.mod,  book.rva ) )

for note in dbgComment.GetCommentList():
    print( "note: {}  {}+{:#x}".format( note.text, note.mod,  note.rva ) )

for label in dbgLabel.GetLabelList():
    print( "label: {}  {}+{:#x}".format( label.text, label.mod,  label.rva ) )


# for sym in dbgSymbol.GetSymbolList():
#     {  }

# for func in dbgFunction.GetFunctionList():
#     {  }

# for argument in dbgArgument.GetArgumentList():
#     {  }


print( "id: {}, handle: {:#x}".format( dbgProcess.ProcessId(), dbgProcess.NativeHandle() ) )

print(
    "peb: {:#x}\nteb: {:#x}".format( 
        dbgMisc.ParseExpression("peb()"), dbgMisc.ParseExpression("teb()")
    )
)

assert( dbgMisc.ResolveLabel("LoadLibraryA") == \
    dbgMisc.RemoteGetProcAddress("kernel32.dll", "LoadLibraryA") )

a, b = dbgGui.SelectionGet( dbgGui.DBGGUIWINDOW.DisassemblyWindow )
dbgGui.SelectionSet( dbgGui.DBGGUIWINDOW.DisassemblyWindow, a + 10, b + 10 )
a, b = dbgGui.SelectionGet( dbgGui.DBGGUIWINDOW.DisassemblyWindow )
print( "CPU Viewer: {:#x}-{:#x}\npc: {:#x}  flags:{:#x}".format( a, b, \
    dbgRegister.GetRegister(dbgRegister.DBGREGISTERENUM.CIP),
    dbgRegister.GetRegister(dbgRegister.DBGREGISTERENUM.CFLAGS) ) )

for m in dbgMemory.MemMaps():
    print( "{:#x}  {:#x}  {}  {}  {}".format(
        m.BaseAddress, m.RegionSize, 
        dbgMemory.MEM_TYPE.str(m.Type), dbgMemory.MEM_PROTECT.str(m.Protect), 
        m.info ) )

for m in dbgModule.GetModuleList():
    print( "{:#x}  {:#x}  {}".format(
        m.base, m.size, m.path
    ) )

for s in dbgModule.GetMainModuleSectionList():
    print( "{:#x}  {:#x}  {}".format(
        s.addr, s.size, s.name
    ) )

m = dbgModule.GetMainModuleInfo()
print( "{:#x}  {:#x}  {}".format(
    m.base, m.size, m.path
) )

for iat in dbgModule.GetImportsFromAddr( m.base ):
    print( "{:#x}  {}".format(
        iat.iatVa, iat.name
    ) )

for eat in dbgModule.GetExportsFromAddr( m.base ):
    print( "{:#x}  {}".format(
        eat.rva, eat.name
    ) )


for t in dbgThread.GetThreadList():
    print( "id:{} entry:{:#x} teb:{:#x} suspend:{} name:{}".format(
        t.ThreadId, t.ThreadStartAddress, 
        t.ThreadLocalBase, t.SuspendCount, t.threadName) )


''' SHELLCODE '''
PAYLOAD = open("test\\BINMSG.BIN", "rb").read()
remoteaddr = dbgMemory.Alloc( 4096 )
dbgMemory.Write( remoteaddr, PAYLOAD ); dbgThread.CreateThread( remoteaddr, 0 )


''' FLIRT '''
from pyflirt.signature import idasig
from pyflirt.flirt import matcher

# Search for code sections
sec = dbgModule.GetMainModuleSectionList()[0]

# Pull memory, create matcher
m = matcher(sec.addr, sec.size)

# vs2022 signature
sign = idasig(
    open("test\\{}\\VisualStudio2022.sig".format( 
    "64" if (X64DBGINFO.x64dbg) else "32"), "rb").read())

for fn in m.match(sign):
    dbgLabel.Set( fn.addr, fn.name )
    print( "found: {:#x}  {}".format( fn.addr, fn.name ) )


''' BYE '''