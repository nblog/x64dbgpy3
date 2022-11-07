#pragma once


#include <array>

#define FMT_HEADER_ONLY
#include "third_party/fmt-9.1.0/include/fmt/format.h"



namespace x64dbgSvrUtil {

    struct reqBuffer {
        /* test => 74 65 73 74 */
        static const std::string serialize(const std::string& buffer) {
            return fmt::format("{:x}",
                fmt::join(std::vector<uint8_t>(buffer.begin(), buffer.end()), " "));
        }
        /* 74 65 73 74 => test */
        static const std::string deserialize(const std::string& buffer) {
            std::string b = std::string();

            std::regex ws_re("\\s+");
            std::vector<std::string> v(
                std::sregex_token_iterator(buffer.begin(), buffer.end(), ws_re, -1),
                std::sregex_token_iterator());
            for (auto&& s : v)
                b.append(1, uint8_t(strtoul(s.c_str(), 0, 16)));
            return b;
        }
    };
}




namespace x64dbgSvrWrapper {

    typedef duint ptr_t;


    namespace dbgNS {

        struct MODULE_IMPORT_WRAPPER {
            ptr_t iatRva;
            ptr_t iatVa;
            ptr_t ordinal;
            std::string name;
            std::string undecoratedName;
        };
        NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(MODULE_IMPORT_WRAPPER, \
            iatRva, iatVa, ordinal, name, undecoratedName)
        struct MODULE_EXPORT_WRAPPER {
            ptr_t ordinal;
            ptr_t rva;
            ptr_t va;
            bool forwarded;
            std::string forwardName;
            std::string name;
            std::string undecoratedName;
        };
        NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(MODULE_EXPORT_WRAPPER, \
            ordinal, rva, va, forwarded, forwardName, name, undecoratedName)
        struct MODULE_SECTION_INFO_WRAPPER {
            ptr_t addr;
            size_t size;
            std::string name;
        };
        NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(MODULE_SECTION_INFO_WRAPPER, \
            addr, size, name)
        struct MODULE_INFO_WRAPPER {
            ptr_t base;
            size_t size;
            ptr_t entry;
            int32_t sectionCount;
            std::string name;
            std::string path;
        };
        NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(MODULE_INFO_WRAPPER, \
            base, size, entry, sectionCount, name, path)

        struct THREAD_INFO_WRAPPER {
            /* THREADINFO */
            int32_t ThreadNumber;
            ptr_t Handle;
            uint32_t ThreadId;
            ptr_t ThreadStartAddress;
            ptr_t ThreadLocalBase;
            std::string threadName;
            /* THREADALLINFO */
            ptr_t ThreadCip;
            uint32_t SuspendCount;
        };
        NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(THREAD_INFO_WRAPPER, \
            ThreadNumber, Handle, ThreadId, ThreadStartAddress, ThreadLocalBase, threadName, ThreadCip, SuspendCount)
        
        /* https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information */
        struct MEMORY_INFO_WRAPPER {
            ptr_t BaseAddress;
            ptr_t AllocationBase;
            uint32_t AllocationProtect;
            size_t RegionSize;
            uint32_t State;
            uint32_t Protect;
            uint32_t Type;
        };
        NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(MEMORY_INFO_WRAPPER, \
            BaseAddress, AllocationBase, AllocationProtect, RegionSize, State, Protect, Type)
    }


    namespace dbgLogging {
        auto logclear() {
            return GuiLogClear();
        }

        auto logprint(const std::string& text) {
            return _plugin_logprint(text.c_str());
        }

        auto logputs(const std::string& text) {
            return _plugin_logputs(text.c_str());
        }
    }


    namespace dbgMisc {
        auto IsDebugging() {
            return DbgIsDebugging();
        }

        auto ParseExpression(const std::string& expr) {
            duint v = 0;
            return Script::Misc::ParseExpression(expr.c_str(), &v) ? v : 0;
        }

        auto RemoteGetProcAddress(const std::string& m, const std::string& a) {
            return Script::Misc::RemoteGetProcAddress(m.c_str(), a.c_str());
        }

        auto ResolveLabel(const std::string& l) {
            return Script::Misc::ResolveLabel(l.c_str());
        }
    }


    namespace dbgGui {
        auto Refresh() {
            return Script::Gui::Refresh();
        }
        auto Message(const std::string& msg) {
            return Script::Gui::Message(msg.c_str());
        }
        auto MessageYesNo(const std::string& msg) {
            return Script::Gui::MessageYesNo(msg.c_str());
        }
        auto FocusView(int32_t win) {
            return GuiFocusView(GUISELECTIONTYPE(win));
        }
        auto SelectionSet(int32_t win, ptr_t a, ptr_t b) {
            SELECTIONDATA select = { a, b };
            return GuiSelectionSet(GUISELECTIONTYPE(win), &select);
        }
        auto SelectionGet(int32_t win) {
            SELECTIONDATA select = { 0, 0 };
            GuiSelectionGet(GUISELECTIONTYPE(win), &select);
            return std::array<ptr_t, 2>{ select.start, select.end };
        }
    }


    namespace dbgPattern {
        auto FindPattern(ptr_t addr, const std::string& pattern) {
            std::string fmtV = fmt::format("findall {:x},{}", addr, pattern);
            return DbgCmdExecDirect(fmtV.c_str());
        }
    }


    namespace dbgAssembler {
        auto AssembleMem(ptr_t addr, const std::string& ins) {
            return Script::Assembler::AssembleMem(addr, ins.c_str());
        }
    }


    namespace dbgSymbol {
        auto GetSymbolList() {  }
    }

    namespace dbgBookmark {
        auto GetBookmarkList() {  }
    }

    namespace dbgComment {
        auto GetCommentList() {  }
    }

    namespace dbgLabel {
        auto GetLabelList() {  }
    }

    namespace dbgArgument {
        auto GetArgumentList() {  }
    }

    namespace dbgFunction {
        auto GetFunctionList() {  }
    }


    namespace dbgModule {

        auto GetModuleList() { 
            nlohmann::json modules;

            BridgeList<Script::Module::ModuleInfo> list;

            if (!Script::Module::GetList(&list))
                return modules;

            for (int i = 0; i < list.Count(); i++) {
                modules[i] = dbgNS::MODULE_INFO_WRAPPER{
                    list[i].base,
                    list[i].size,
                    list[i].entry,
                    list[i].sectionCount,
                    list[i].name,
                    list[i].path
                };
            } return modules;
        }

        auto GetMainModuleInfo() {  
            Script::Module::ModuleInfo m{};
            Script::Module::GetMainModuleInfo(&m);
            return nlohmann::json() = dbgNS::MODULE_INFO_WRAPPER{
                    m.base, m.size, m.entry, m.sectionCount,
                    m.name, m.path
            };
        }

        auto InfoFromAddr(ptr_t addr) {
            Script::Module::ModuleInfo m{};
            Script::Module::InfoFromAddr(addr, &m);
            return nlohmann::json() = dbgNS::MODULE_INFO_WRAPPER{
                m.base, m.size, m.entry, m.sectionCount,
                m.name, m.path
            };
        }

        auto InfoFromName(const std::string& n) {
            Script::Module::ModuleInfo m{};
            Script::Module::InfoFromName(n.c_str(), &m);
            return nlohmann::json() = dbgNS::MODULE_INFO_WRAPPER{
                m.base, m.size, m.entry, m.sectionCount,
                m.name, m.path
            };
        }

        auto GetMainModuleSectionList() {  
            nlohmann::json sections;

            BridgeList<Script::Module::ModuleSectionInfo> list;

            if (!Script::Module::GetMainModuleSectionList(&list))
                return sections;

            for (int i = 0; i < list.Count(); i++) {
                sections[i] = dbgNS::MODULE_SECTION_INFO_WRAPPER{
                    list[i].addr, list[i].size, list[i].name
                };
            } return sections;
        }

        auto SectionListFromAddr(ptr_t addr) {  
            nlohmann::json sections;
            BridgeList<Script::Module::ModuleSectionInfo> list;

            if (!Script::Module::SectionListFromAddr(addr, &list))
                return sections;

            for (int i = 0; i < list.Count(); i++) {
                sections[i] = dbgNS::MODULE_SECTION_INFO_WRAPPER{
                    list[i].addr, list[i].size, list[i].name
                };
            } return sections;
        }

        auto SectionListFromName(const std::string& n) {  
            nlohmann::json sections;
            BridgeList<Script::Module::ModuleSectionInfo> list;

            if (!Script::Module::SectionListFromName(n.c_str(), &list))
                return sections;

            for (int i = 0; i < list.Count(); i++) {
                sections[i] = dbgNS::MODULE_SECTION_INFO_WRAPPER{
                    list[i].addr, list[i].size, list[i].name
                };
            } return sections;
        }

        auto GetExportsFromAddr(ptr_t addr) {
            nlohmann::json exports;

            Script::Module::ModuleInfo m = { addr };

            BridgeList<Script::Module::ModuleExport> list;

            if (!Script::Module::GetExports(&m, &list))
                return exports;

            for (int i = 0; i < list.Count(); i++) {
                exports[i] = dbgNS::MODULE_EXPORT_WRAPPER{
                    list[i].ordinal,
                    list[i].rva,
                    list[i].va,
                    list[i].forwarded,
                    list[i].forwardName,
                    list[i].name,
                    list[i].undecoratedName
                };
            } return exports;
        }

        auto GetImportsFromAddr(ptr_t addr) {
            nlohmann::json imports;

            Script::Module::ModuleInfo m = { addr };
            
            BridgeList<Script::Module::ModuleImport> list;

            if (!Script::Module::GetImports(&m, &list))
                return imports;

            for (int i = 0; i < list.Count(); i++) {
                imports[i] = dbgNS::MODULE_IMPORT_WRAPPER{
                    list[i].iatRva,
                    list[i].iatVa,
                    list[i].ordinal,
                    list[i].name,
                    list[i].undecoratedName
                };
            } return imports;
        }
    }


    namespace dbgThread {
        
        auto GetThreadList() {
            nlohmann::json threads;

            THREADLIST tl{};
            DbgGetThreadList(&tl);
            for (int i = 0; i < tl.count; i++) {
                threads[i] = dbgNS::THREAD_INFO_WRAPPER{
                    tl.list[i].BasicInfo.ThreadNumber,
                    ptr_t(tl.list[i].BasicInfo.Handle),
                    tl.list[i].BasicInfo.ThreadId,
                    tl.list[i].BasicInfo.ThreadStartAddress,
                    tl.list[i].BasicInfo.ThreadLocalBase,
                    tl.list[i].BasicInfo.threadName,
                    tl.list[i].ThreadCip,
                    tl.list[i].SuspendCount,
                };
            }
            BridgeFree(tl.list); return threads;
        }

        auto GetFirstThreadId() {
            for (const auto& t : dbgThread::GetThreadList()) {
                if (0 == t["BasicInfo"]["ThreadNumber"]) {
                    return uint32_t(t["BasicInfo"]["ThreadId"]);
                }
            }
            return uint32_t(0);
        }

        auto GetActiveThreadId() {
            return uint32_t(DbgGetThreadId());
        }
        auto SetActiveThreadId(uint32_t threadId) {
            std::string fmtV = fmt::format("switchthread {:x}", threadId);
            return DbgCmdExecDirect(fmtV.c_str());
        }
        auto SuspendThreadId(uint32_t threadId) { 
            std::string fmtV = fmt::format("suspendthread {:x}", threadId);
            return DbgCmdExecDirect(fmtV.c_str());
        }
        auto ResumeThreadId(uint32_t threadId) {
            std::string fmtV = fmt::format("resumethread {:x}", threadId);
            return DbgCmdExecDirect(fmtV.c_str());
        }
        auto KillThread(uint32_t threadId, uint32_t exitcode) {
            std::string fmtV = fmt::format("killthread {:x},{:x}", threadId, exitcode);
            return DbgCmdExecDirect(fmtV.c_str());
        }
        auto CreateThread(ptr_t entry, ptr_t arg) { 
            std::string fmtV = fmt::format("createthread {:x},{:x}", entry, arg);
            return DbgCmdExecDirect(fmtV.c_str());
        }
    }

    namespace dbgProcess {
        auto ProcessId() { return uint32_t(DbgGetProcessId()); }
        auto NativeHandle() { return ptr_t(DbgGetProcessHandle()); }
    }


    namespace dbgMemory {
        auto MemMaps() {
            nlohmann::json mmaps;

            MEMMAP maps{};
            DbgMemMap(&maps);
            for (int i = 0; i < maps.count; i++) {
                mmaps[i] = dbgNS::MEMORY_INFO_WRAPPER{
                    ptr_t(maps.page[i].mbi.BaseAddress),
                    ptr_t(maps.page[i].mbi.AllocationBase),
                    maps.page[i].mbi.AllocationProtect,
                    maps.page[i].mbi.RegionSize,
                    maps.page[i].mbi.State,
                    maps.page[i].mbi.Protect,
                    maps.page[i].mbi.Type
                };
                mmaps[i]["info"] = maps.page[i].info;
            }
            BridgeFree(maps.page); return mmaps;
        }
        auto ValidPtr(ptr_t addr) { 
            return Script::Memory::IsValidPtr(addr);
        }
        auto Read(ptr_t addr, size_t size) {
            std::string reqbuff(size, '\00');
            Script::Memory::Read(addr, reqbuff.data(), reqbuff.size(), 0);
            return x64dbgSvrUtil::reqBuffer::serialize(reqbuff);
        }
        auto Write(ptr_t addr, const std::string& reqbuff) {
            std::string buffer = x64dbgSvrUtil::reqBuffer::deserialize(reqbuff);
            return Script::Memory::Write(addr, buffer.data(), buffer.size(), 0);
        }
        auto Free(ptr_t addr) {
            return Script::Memory::RemoteFree(addr);
        }
        auto Alloc(ptr_t addr, size_t size) {
            return Script::Memory::RemoteAlloc(addr, duint(size));
        }
        auto Base(ptr_t addr, bool reserved, bool cache) { 
            return Script::Memory::GetBase(addr, reserved, cache);
        }
        auto Size(ptr_t addr, bool reserved, bool cache) { 
            return Script::Memory::GetSize(addr, reserved, cache);
        }
    }

    namespace dbgStack {
        auto Pop() { return Script::Stack::Pop(); }
        auto Push(ptr_t value) { return Script::Stack::Push(value); }
    }

    namespace dbgRegister {
        auto GetFlag(int32_t f) { return Script::Flag::Get(Script::Flag::FlagEnum(f)); }
        auto SetFlag(int32_t f, bool v) { return Script::Flag::Set(Script::Flag::FlagEnum(f), v); }

        auto GetRegister(int32_t r) { return Script::Register::Get(Script::Register::RegisterEnum(r)); }
        auto SetRegister(int32_t r, ptr_t v) { return Script::Register::Set(Script::Register::RegisterEnum(r), v); }
    }

    namespace dbgDebug {
        auto Stop() { return Script::Debug::Stop(); }
        auto Run() { return Script::Debug::Run(); }
        auto StepIn() { return Script::Debug::StepIn(); }
        auto StepOver() { return Script::Debug::StepOver(); }
        auto StepOut() { return Script::Debug::StepOut(); }

        auto SetBreakpoint(ptr_t addr) { 
            return Script::Debug::SetBreakpoint(addr); 
        }
        auto DeleteBreakpoint(ptr_t addr) {
            return Script::Debug::DeleteBreakpoint(addr);
        }
        auto DisableBreakpoint(ptr_t addr) { 
            return Script::Debug::DisableBreakpoint(addr); 
        }

        auto SetHardwareBreakpoint(ptr_t addr, int32_t hard) {
            return Script::Debug::SetHardwareBreakpoint(addr, Script::Debug::HardwareType(hard)); 
        }
        auto DeleteHardwareBreakpoint(ptr_t addr) {
            return Script::Debug::DeleteHardwareBreakpoint(addr); 
        }
    }
};