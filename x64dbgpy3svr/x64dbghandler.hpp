#pragma once

#include <array>
#include <memory>
#include <optional>
#include "plugintemplate/plugin.h"
#include "plugintemplate/pluginsdk/lz4/lz4.h"
#ifdef _WIN64
#pragma comment(lib, "pluginsdk/lz4/lz4_x64.lib")
#else
#pragma comment(lib, "pluginsdk/lz4/lz4_x86.lib")
#endif

#define FMT_HEADER_ONLY
#include "third_party/fmt/include/fmt/format.h"


namespace x64dbgSvrUtil {
    struct RequestBuffer {
        static const std::string Serialize(const std::string& buffer) {
			throw std::runtime_error("Not implemented");
        }
        static const std::string Deserialize(const std::string& buffer) {
			throw std::runtime_error("Not implemented");
        }
    };
};


namespace x64dbgSvrWrapper {
    using ptr_t = duint;

    static void rtcmsgbox(const std::string& msg) {
        return Script::Gui::Message(msg.c_str());
    }

    static std::vector<uint8_t> PluginIcon() {
        return std::vector<uint8_t>();
    }
};

namespace x64dbgSvrWrapper::dbgUtils {
    /* BASIC_INSTRUCTION_INFO */
    struct INSTRUCTION_INFO_WRAPPER {
        uint32_t type;
        ptr_t addr;
        bool branch, call;
        int size;
        std::string instruction;
    };
    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(INSTRUCTION_INFO_WRAPPER, \
        type, addr, branch, call, size, instruction)

    /* BRIDGEBP */
    struct BREAKPOINT_INFO_WRAPPER {
        int32_t type; /* BPXTYPE */
        ptr_t addr;
        bool enabled, singleshoot, active;
        std::string name;
        std::string mod;
        uint32_t hitCount;
        std::string breakCondition;
        std::string logCondition;
        std::string commandCondition;
        std::string logText;
        std::string commandText;
    };
    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(BREAKPOINT_INFO_WRAPPER, \
        type, addr, enabled, singleshoot, active, name, mod, hitCount,
        breakCondition, logCondition, commandCondition, logText, commandText)

    struct ARGUMENT_INFO_WRAPPER {
        std::string mod;
        ptr_t rvaStart;
        ptr_t rvaEnd;
        bool manual;
        ptr_t instructioncount;
    };
    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(ARGUMENT_INFO_WRAPPER, \
        mod, rvaStart, rvaEnd, manual, instructioncount)

    struct FUNCTION_INFO_WRAPPER {
        std::string mod;
        ptr_t rvaStart;
        ptr_t rvaEnd;
        bool manual;
        ptr_t instructioncount;
    };
    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(FUNCTION_INFO_WRAPPER, \
        mod, rvaStart, rvaEnd, manual, instructioncount)

    struct LABEL_INFO_WRAPPER {
        std::string mod;
        ptr_t rva;
        std::string text;
        bool manual;
    };
    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(LABEL_INFO_WRAPPER, \
        mod, rva, text, manual)

    struct COMMENT_INFO_WRAPPER {
        std::string mod;
        ptr_t rva;
        std::string text;
        bool manual;
    };
    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(COMMENT_INFO_WRAPPER, \
        mod, rva, text, manual)

    struct BOOKMARK_INFO_WRAPPER {
        std::string mod;
        ptr_t rva;
        bool manual;
    };
    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(BOOKMARK_INFO_WRAPPER, \
        mod, rva, manual)

    struct SYMBOL_INFO_WRAPPER {
        std::string mod;
        ptr_t rva;
        std::string name;
        bool manual;
        int32_t type; /* Script::Symbol::SymbolType */
    };
    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(SYMBOL_INFO_WRAPPER, \
        mod, rva, name, manual, type)

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
};

namespace x64dbgSvrWrapper::dbgLogging {
    auto logclear() {
        return GuiLogClear();
    }

    auto logputs(const std::string& text) {
        return _plugin_logputs(text.c_str());
    }

    auto logprint(const std::string& text) {
        return _plugin_logprint(text.c_str());
    }

    template <typename... Args>
	auto logprintf(const std::string& fmt, Args&&... args) {
        return;
	}
};

namespace x64dbgSvrWrapper::dbgMisc {
    auto IsDebugging() {
        return DbgIsDebugging();
    }

    auto IsRunning() {
        return DbgIsRunning();
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
};

namespace x64dbgSvrWrapper::dbgGui {
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
};

namespace x64dbgSvrWrapper::dbgPattern {
    auto FindPattern(ptr_t addr, const std::string& pattern) {
        std::string fmtV = fmt::format("findallmem {:x},{}", addr, pattern);
        return DbgCmdExecDirect(fmtV.c_str());
    }
};

namespace x64dbgSvrWrapper::dbgAssembler {
    auto Assemble(ptr_t addr, const std::string& ins) {
        return DbgAssembleAt(addr, ins.c_str());
    }

    auto DisasmFast(ptr_t addr) {
        nlohmann::json disasm;

        BASIC_INSTRUCTION_INFO info{};
        DbgDisasmFastAt(addr, &info);

        disasm = dbgUtils::INSTRUCTION_INFO_WRAPPER{
            info.type,
            info.addr,
            info.branch, info.call,
            info.size,
            info.instruction
        };
        return disasm;
    }
};

namespace x64dbgSvrWrapper::dbgSymbol {
    auto GetSymbolList() {
        nlohmann::json symbols;

        BridgeList<Script::Symbol::SymbolInfo> list;

        if (!Script::Symbol::GetList(&list))
            return symbols;

        for (int i = 0; i < list.Count(); i++) {
            symbols[i] = dbgUtils::SYMBOL_INFO_WRAPPER{
                list[i].mod,
                list[i].rva,
                list[i].name,
                list[i].manual,
                list[i].type
            };
        } return symbols;
    }
};

namespace x64dbgSvrWrapper::dbgBookmark {
    auto GetBookmarkList() {
        nlohmann::json bookmarks;

        BridgeList<Script::Bookmark::BookmarkInfo> list;

        if (!Script::Bookmark::GetList(&list))
            return bookmarks;

        for (int i = 0; i < list.Count(); i++) {
            bookmarks[i] = dbgUtils::BOOKMARK_INFO_WRAPPER{
                list[i].mod,
                list[i].rva,
                list[i].manual
            };
        } return bookmarks;
    }
};

namespace x64dbgSvrWrapper::dbgComment {
    auto GetCommentList() {
        nlohmann::json comments;

        BridgeList<Script::Comment::CommentInfo> list;

        if (!Script::Comment::GetList(&list))
            return comments;

        for (int i = 0; i < list.Count(); i++) {
            comments[i] = dbgUtils::COMMENT_INFO_WRAPPER{
                list[i].mod,
                list[i].rva,
                list[i].text,
                list[i].manual
            };
        } return comments;
    }
};

namespace x64dbgSvrWrapper::dbgLabel {
    auto GetLabelList() {
        nlohmann::json labels;

        BridgeList<Script::Label::LabelInfo> list;

        if (!Script::Label::GetList(&list))
            return labels;

        for (int i = 0; i < list.Count(); i++) {
            labels[i] = dbgUtils::LABEL_INFO_WRAPPER{
                list[i].mod,
                list[i].rva,
                list[i].text,
                list[i].manual
            };
        } return labels;
    }

    auto Set(ptr_t addr, const std::string& text, bool manual, bool temporary) {
        return Script::Label::Set(addr, text.c_str(), manual, temporary);
    }

    auto Del(ptr_t addr) {
        return Script::Label::Delete(addr);
    }
};

namespace x64dbgSvrWrapper::dbgFunction {
    auto GetFunctionList() {
        nlohmann::json functions;

        BridgeList<Script::Function::FunctionInfo> list;

        if (!Script::Function::GetList(&list))
            return functions;

        for (int i = 0; i < list.Count(); i++) {
            functions[i] = dbgUtils::FUNCTION_INFO_WRAPPER{
                list[i].mod,
                list[i].rvaStart,
                list[i].rvaEnd,
                list[i].manual,
                list[i].instructioncount
            };
        } return functions;
    }
};

namespace x64dbgSvrWrapper::dbgArgument {
    auto GetArgumentList() {
        nlohmann::json arguments;

        BridgeList<Script::Argument::ArgumentInfo> list;

        if (!Script::Argument::GetList(&list))
            return arguments;

        for (int i = 0; i < list.Count(); i++) {
            arguments[i] = dbgUtils::ARGUMENT_INFO_WRAPPER{
                list[i].mod,
                list[i].rvaStart,
                list[i].rvaEnd,
                list[i].manual,
                list[i].instructioncount
            };
        } return arguments;
    }
};

namespace x64dbgSvrWrapper::dbgModule {
    auto GetModuleList() {
        nlohmann::json modules;

        BridgeList<Script::Module::ModuleInfo> list;

        if (!Script::Module::GetList(&list))
            return modules;

        for (int i = 0; i < list.Count(); i++) {
            modules[i] = dbgUtils::MODULE_INFO_WRAPPER{
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
        return nlohmann::json() = dbgUtils::MODULE_INFO_WRAPPER{
                m.base, m.size, m.entry, m.sectionCount,
                m.name, m.path
        };
    }

    auto InfoFromAddr(ptr_t addr) {
        Script::Module::ModuleInfo m{};
        Script::Module::InfoFromAddr(addr, &m);
        return nlohmann::json() = dbgUtils::MODULE_INFO_WRAPPER{
            m.base, m.size, m.entry, m.sectionCount,
            m.name, m.path
        };
    }

    auto InfoFromName(const std::string& n) {
        Script::Module::ModuleInfo m{};
        Script::Module::InfoFromName(n.c_str(), &m);
        return nlohmann::json() = dbgUtils::MODULE_INFO_WRAPPER{
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
            sections[i] = dbgUtils::MODULE_SECTION_INFO_WRAPPER{
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
            sections[i] = dbgUtils::MODULE_SECTION_INFO_WRAPPER{
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
            sections[i] = dbgUtils::MODULE_SECTION_INFO_WRAPPER{
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
            exports[i] = dbgUtils::MODULE_EXPORT_WRAPPER{
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
            imports[i] = dbgUtils::MODULE_IMPORT_WRAPPER{
                list[i].iatRva,
                list[i].iatVa,
                list[i].ordinal,
                list[i].name,
                list[i].undecoratedName
            };
        } return imports;
    }
};

namespace x64dbgSvrWrapper::dbgThread {
    auto GetThreadList() {
        nlohmann::json threads;

        THREADLIST list{};

		DbgGetThreadList(&list);

        for (int i = 0; i < list.count; i++) {
            threads[i] = dbgUtils::THREAD_INFO_WRAPPER{
                list.list[i].BasicInfo.ThreadNumber,
                ptr_t(list.list[i].BasicInfo.Handle),
                list.list[i].BasicInfo.ThreadId,
                list.list[i].BasicInfo.ThreadStartAddress,
                list.list[i].BasicInfo.ThreadLocalBase,
                list.list[i].BasicInfo.threadName,
                list.list[i].ThreadCip,
                list.list[i].SuspendCount,
            };
        }
        BridgeFree(list.list); return threads;
    }

    auto GetFirstThreadId() {
        for (const auto& t : dbgThread::GetThreadList()) {
            if (0 == t["BasicInfo"]["ThreadNumber"]) {
                return uint32_t(t["BasicInfo"]["ThreadId"]);
            }
        }
        return uint32_t(GuiGetMainThreadId());
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
};

namespace x64dbgSvrWrapper::dbgProcess {
    auto ProcessId() { return uint32_t(DbgGetProcessId()); }
    auto NativeHandle() { return ptr_t(DbgGetProcessHandle()); }
};

namespace x64dbgSvrWrapper::dbgMemory {
    auto MemMaps() {
        nlohmann::json mmaps;

        MEMMAP maps{};
        if (!DbgMemMap(&maps))
            return mmaps;

        for (int i = 0; i < maps.count; i++) {
            mmaps[i] = dbgUtils::MEMORY_INFO_WRAPPER{
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
        return x64dbgSvrUtil::RequestBuffer::Serialize(reqbuff);
    }
    auto Write(ptr_t addr, const std::string& reqbuff) {
        std::string buffer = x64dbgSvrUtil::RequestBuffer::Deserialize(reqbuff);
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
        return size_t(Script::Memory::GetSize(addr, reserved, cache));
    }
};

namespace x64dbgSvrWrapper::dbgStack {
    auto Pop() { return Script::Stack::Pop(); }
    auto Push(ptr_t value) { return Script::Stack::Push(value); }
};

namespace x64dbgSvrWrapper::dbgRegister {
    auto GetFlag(int32_t f) { return Script::Flag::Get(Script::Flag::FlagEnum(f)); }
    auto SetFlag(int32_t f, bool v) { return Script::Flag::Set(Script::Flag::FlagEnum(f), v); }

    auto GetRegister(int32_t r) { return Script::Register::Get(Script::Register::RegisterEnum(r)); }
    auto SetRegister(int32_t r, ptr_t v) { return Script::Register::Set(Script::Register::RegisterEnum(r), v); }
};

namespace x64dbgSvrWrapper::dbgDebug {
    auto Stop() { Script::Debug::Stop(); }
    auto Run() { Script::Debug::Run(); }
    auto StepIn() { Script::Debug::StepIn(); }
    auto StepOver() { Script::Debug::StepOver(); }
    auto StepOut() { Script::Debug::StepOut(); }

    auto GetBreakpointList(int32_t bpxtype) {
        nlohmann::json breaks;

        BPMAP bps{};
        if (!DbgGetBpList(BPXTYPE(bpxtype), &bps))
            return breaks;

        for (int i = 0; i < bps.count; i++) {
            breaks[i] = dbgUtils::BREAKPOINT_INFO_WRAPPER{
                bps.bp[i].type,
                bps.bp[i].addr,
                bps.bp[i].enabled, bps.bp[i].singleshoot, bps.bp[i].active,
                bps.bp[i].name, bps.bp[i].mod,
                bps.bp[i].hitCount,
                bps.bp[i].breakCondition,
                bps.bp[i].logCondition,
                bps.bp[i].commandCondition,
                bps.bp[i].logText,
                bps.bp[i].commandText,
            };
        }
        BridgeFree(bps.bp); return breaks;
    }

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
};