#!/usr/bin/env python3
# coding=utf-8

import time

from x64dbgpy3.x64dbgpyt3 import *




dbgLogging.logclear()
dbgLogging.logputs("hello python3")
dbgLogging.logprint("hello "), dbgLogging.logprint("python3\n")



if (dbgMisc.IsDebugging()):
    '''  '''

    print( "id: {}, handle: {:#x}".format( dbgProcess.ProcessId(), dbgProcess.NativeHandle() ) )

    print(
        "peb: {:#x}\nteb: {:#x}".format( 
            dbgMisc.ParseExpression("peb()"), dbgMisc.ParseExpression("teb()")
        )
    )

    assert( dbgMisc.ResolveLabel("LoadLibraryA") == \
        dbgMisc.RemoteGetProcAddress("kernel32.dll", "LoadLibraryA") )


    a,b = dbgGui.SelectionGet( dbgGui.DBGGUIWINDOW.DisassemblyWindow )
    print( "CPU Viewer: {:#x}-{:#x}\npc: {:#x}  flags:{:#x}".format( a, b, \
        dbgRegister.GetRegister(dbgRegister.DBGREGISTERENUM.CIP) ,
        dbgRegister.GetRegister(dbgRegister.DBGREGISTERENUM.CFLAGS) ) )

    dbgGui.SelectionSet( dbgGui.DBGGUIWINDOW.DisassemblyWindow, a + 10, b + 10 )

    for m in dbgMemory.MemMaps():
        print( "{:#x}  {:#x}  {}  {}  {}".format(
            m.BaseAddress, m.RegionSize, 
            dbgMemory.MEM_TYPE.str(m.Type), dbgMemory.MEM_PROTECT.str(m.Protect), 
            m.info ) )


    for t in dbgThread.GetThreadList():
        print( "id:{} entry:{:#x} teb:{:#x} suspend:{} name:{}".format(
            t.ThreadId, t.ThreadStartAddress, 
            t.ThreadLocalBase, t.SuspendCount, t.threadName) )


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


    ''' HELLO  '''
    MSGBIN = open("test\\BINMSG.BIN", "rb").read()
    remoteaddr = dbgMemory.Alloc( 4096 )
    dbgMemory.Write( remoteaddr, MSGBIN ), time.sleep(1)

    dbgDebug.Run(), time.sleep(1), \
        dbgThread.CreateThread( remoteaddr, 0 )

else: dbgGui.Message( "please start debugging" )