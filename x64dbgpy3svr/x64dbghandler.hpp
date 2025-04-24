#pragma once

#include <array>
#include <memory>
#include <optional>

#define FMT_HEADER_ONLY
#include "third_party/fmt/include/fmt/format.h"

#include "plugintemplate/plugin.h"
#include "plugintemplate/pluginsdk/lz4/lz4.h"
#ifdef _WIN64
#pragma comment(lib, "pluginsdk/lz4/lz4_x64.lib")
#else
#pragma comment(lib, "pluginsdk/lz4/lz4_x86.lib")
#endif

#include "third_party/simdutf-6.5.0/singleheader/simdutf.cpp"
#include "third_party/simdutf-6.5.0/singleheader/simdutf.h"


namespace x64dbgSvrUtil {
    struct RequestBuffer {
        static const size_t hdr_size = sizeof(uint32_t);

        static std::string Serialize(const std::vector<uint8_t>& buffer) {
            int maxCompressedSize = LZ4_compressBound(static_cast<int>(buffer.size()));
            std::vector<uint8_t> compressed(maxCompressedSize + hdr_size);
            *reinterpret_cast<uint32_t*>(compressed.data()) = static_cast<uint32_t>(buffer.size());

            int compressedSize = LZ4_compress(
                reinterpret_cast<const char*>(buffer.data()),
                reinterpret_cast<char*>(compressed.data() + hdr_size),
                static_cast<int>(buffer.size())
            );
			if (compressedSize < 0) {
				throw std::runtime_error("Compression failed");
			}

            compressed.resize(compressedSize + hdr_size);

            std::vector<char> base64buffer(simdutf::base64_length_from_binary(compressed.size()));
            simdutf::binary_to_base64(
                reinterpret_cast<const char*>(compressed.data()),
                compressed.size(),
                base64buffer.data()
            );

            return std::string(base64buffer.data(), base64buffer.size());
        }

        static std::vector<uint8_t> Deserialize(const std::string& base64buffer) {
            std::vector<char> compressed(simdutf::maximal_binary_length_from_base64(
                base64buffer.data(), base64buffer.size()));

            simdutf::result r = simdutf::base64_to_binary(
                base64buffer.data(), base64buffer.size(), compressed.data());
            if (r.error) {
                throw std::runtime_error("Base64 decoding failed");
            }

            compressed.resize(r.count);

            uint32_t originalSize = *reinterpret_cast<const uint32_t*>(compressed.data());
            std::vector<uint8_t> decompressed(originalSize);

            int decompressedSize = LZ4_decompress_safe(
                reinterpret_cast<const char*>(compressed.data() + hdr_size),
                reinterpret_cast<char*>(decompressed.data()),
                static_cast<int>(compressed.size() - hdr_size),
                static_cast<int>(decompressed.size())
            );

            if (decompressedSize < 0 || static_cast<uint32_t>(decompressedSize) != originalSize) {
                throw std::runtime_error("Decompression failed");
            }

            return decompressed;
        }
    };
};


namespace x64dbgSvrWrapper {
    using ptr_t = duint;
	using size_t = duint;

    static void rtcmsgbox(const std::string& msg) {
        return Script::Gui::Message(msg.c_str());
    }

    static std::vector<uint8_t> PluginIcon() {
        return std::vector<uint8_t>();
    }
};

namespace x64dbgSvrWrapper::dbgUtils {
    /* FILETIME */
	struct FILETIME_WRAPPER {
		uint32_t dwLowDateTime;
		uint32_t dwHighDateTime;
	};
	NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(FILETIME_WRAPPER, \
		dwLowDateTime, dwHighDateTime)

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

    struct WATCH_INFO_WRAPPER {
		std::string WatchName;
		std::string Expression;
		uint32_t window;
		uint32_t id;
		int32_t varType; /* WATCHVARTYPE */
		int32_t watchdogMode; /* WATCHDOGMODE */
		ptr_t value;
		bool watchdogTriggered;
	};
	NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(WATCH_INFO_WRAPPER, \
		WatchName, Expression, window, id, varType, watchdogMode, value, watchdogTriggered)

    struct XREF_RECORD_WRAPPER {
		ptr_t addr;
		int32_t type; /* XREFTYPE */
	};
	NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(XREF_RECORD_WRAPPER, \
		addr, type)
    struct XREF_INFO_WRAPPER {
		size_t refcount;
		std::vector<XREF_RECORD_WRAPPER> xrefs;
    };
	NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(XREF_INFO_WRAPPER, \
		refcount, xrefs)

    struct ARGUMENT_INFO_WRAPPER {
        std::string mod;
        ptr_t rvaStart;
        ptr_t rvaEnd;
        bool manual;
        size_t instructioncount;
    };
    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(ARGUMENT_INFO_WRAPPER, \
        mod, rvaStart, rvaEnd, manual, instructioncount)

    struct FUNCTION_INFO_WRAPPER {
        std::string mod;
        ptr_t rvaStart;
        ptr_t rvaEnd;
        bool manual;
        size_t instructioncount;
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
        ptr_t addr;
        std::string decoratedSymbol;
        std::string undecoratedSymbol;
        int32_t type; /* SYMBOLTYPE */

        // If true: Use BridgeFree(decoratedSymbol) to deallocate
        // Else: The decoratedSymbol pointer is valid until the module unloads
        bool freeDecorated;

        // If true: Use BridgeFree(undecoratedSymbol) to deallcoate
        // Else: The undecoratedSymbol pointer is valid until the module unloads
        bool freeUndecorated;

        // The entry point pseudo-export has ordinal == 0 (invalid ordinal value)
        uint32_t ordinal;
	};
	NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(SYMBOL_INFO_WRAPPER, \
		addr, decoratedSymbol, undecoratedSymbol, type, freeDecorated, freeUndecorated, ordinal)

    struct SYMBOL_INFO2_WRAPPER {
        std::string mod;
        ptr_t rva;
        std::string name;
        bool manual;
        int32_t type; /* Script::Symbol::SymbolType */
    };
    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(SYMBOL_INFO2_WRAPPER, \
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
		int32_t ThreadNumber;
		ptr_t Handle;
		uint32_t ThreadId;
		ptr_t ThreadStartAddress;
		ptr_t ThreadLocalBase;
		std::string threadName;
	};
	NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(THREAD_INFO_WRAPPER, \
		ThreadNumber, Handle, ThreadId, ThreadStartAddress, ThreadLocalBase, threadName)
    struct THREAD_ALL_INFO_WRAPPER {
		THREAD_INFO_WRAPPER BasicInfo;
        ptr_t ThreadCip;
        uint32_t SuspendCount;
		int32_t Priority; /* THREADPRIORITY */
		int32_t WaitReason; /* THREADWAITREASON */
		uint32_t LastError;
        FILETIME_WRAPPER UserTime;
        FILETIME_WRAPPER KernelTime;
        FILETIME_WRAPPER CreationTime;
		uint64_t Cycles; // Windows Vista or greater
    };
	NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(THREAD_ALL_INFO_WRAPPER, \
		BasicInfo, 
		ThreadCip, SuspendCount, Priority, WaitReason, LastError, UserTime, KernelTime, CreationTime, Cycles)

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
        GuiLogClear();
        return nlohmann::json();
    }

    auto logputs(const std::string& text) {
        _plugin_logputs(text.c_str());
        return nlohmann::json();
    }

    auto logprint(const std::string& text) {
        _plugin_logprint(text.c_str());
        return nlohmann::json();
    }
};

namespace x64dbgSvrWrapper::dbgMisc {
	auto Sleep(int32_t s) {
        std::this_thread::sleep_for(std::chrono::seconds(s));
		return nlohmann::json();
	}

    auto GetLabelAt(ptr_t addr) {
        char label[MAX_LABEL_SIZE] = "";
        return DbgGetLabelAt(addr, SEG_DEFAULT, label) ? label : std::string();
    }

	auto GetCommentAt(ptr_t addr) {
		char comment[MAX_COMMENT_SIZE] = "";
		return DbgGetCommentAt(addr, comment) ? comment : std::string();
	}

	auto GetStringAt(ptr_t addr) {
        char string[MAX_STRING_SIZE] = "";
        return DbgGetStringAt(addr, string) ? string : std::string();
	}

	auto GetWatchList() {
		nlohmann::json watches;

        BridgeList<WATCHINFO> list;

        DbgGetWatchList(&list);

		for (int i = 0; i < list.Count(); i++) {
			watches[i] = dbgUtils::WATCH_INFO_WRAPPER{
				list[i].WatchName,
				list[i].Expression,
				list[i].window,
				list[i].id,
				list[i].varType,
				list[i].watchdogMode,
				list[i].value,
				list[i].watchdogTriggered
			};
		} return watches;
	}

    auto ParseExpression(const std::string& expr) {
        duint v = 0;
        return Script::Misc::ParseExpression(expr.c_str(), &v) ? v : 0;
    }

    auto ResolveLabel(const std::string& l) {
        return Script::Misc::ResolveLabel(l.c_str());
    }

    auto RemoteGetProcAddress(const std::string& m, const std::string& a) {
        return Script::Misc::RemoteGetProcAddress(m.c_str(), a.c_str());
    }
};

namespace x64dbgSvrWrapper::dbgGui {
    auto FocusView(int32_t win) {
        GuiFocusView(GUISELECTIONTYPE(win));
        return nlohmann::json();
    }
    auto Refresh() {
        Script::Gui::Refresh();
        return nlohmann::json();
    }
    auto Message(const std::string& msg) {
        Script::Gui::Message(msg.c_str());
        return nlohmann::json();
    }
    auto MessageYesNo(const std::string& msg) {
        return Script::Gui::MessageYesNo(msg.c_str());
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
        DbgCmdExec(fmtV.c_str());
		return nlohmann::json();
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

        Script::Symbol::GetList(&list);

        for (int i = 0; i < list.Count(); i++) {
            symbols[i] = dbgUtils::SYMBOL_INFO2_WRAPPER{
                list[i].mod,
                list[i].rva,
                list[i].name,
                list[i].manual,
                list[i].type
            };
        } return symbols;
    }

	auto Get(ptr_t addr) {
        nlohmann::json sym;

		SYMBOLINFO info{};
		DbgGetSymbolInfoAt(addr, &info);

		sym = dbgUtils::SYMBOL_INFO_WRAPPER{
			info.addr,
			info.decoratedSymbol,
			info.undecoratedSymbol,
			info.type,
			info.freeDecorated,
			info.freeUndecorated,
			info.ordinal
		};

        if (info.freeDecorated) BridgeFree(info.decoratedSymbol);
        if (info.freeUndecorated) BridgeFree(info.undecoratedSymbol);

		return sym;
	}
};

namespace x64dbgSvrWrapper::dbgBookmark {
    auto GetBookmarkList() {
        nlohmann::json bookmarks;

        BridgeList<Script::Bookmark::BookmarkInfo> list;

        Script::Bookmark::GetList(&list);

        for (int i = 0; i < list.Count(); i++) {
            bookmarks[i] = dbgUtils::BOOKMARK_INFO_WRAPPER{
                list[i].mod,
                list[i].rva,
                list[i].manual
            };
        } return bookmarks;
    }

	auto Get(ptr_t addr) {
		Script::Bookmark::BookmarkInfo b{};
		Script::Bookmark::GetInfo(addr, &b);
		return nlohmann::json() = dbgUtils::BOOKMARK_INFO_WRAPPER{
			b.mod,
			b.rva,
			b.manual
		};
	}

	auto Set(ptr_t addr, bool manual) {
		return Script::Bookmark::Set(addr, manual);
	}

	auto Del(ptr_t addr) {
		return Script::Bookmark::Delete(addr);
	}
};

namespace x64dbgSvrWrapper::dbgComment {
    auto GetCommentList() {
        nlohmann::json comments;

        BridgeList<Script::Comment::CommentInfo> list;

        Script::Comment::GetList(&list);

        for (int i = 0; i < list.Count(); i++) {
            comments[i] = dbgUtils::COMMENT_INFO_WRAPPER{
                list[i].mod,
                list[i].rva,
                list[i].text,
                list[i].manual
            };
        } return comments;
    }

    auto Get(ptr_t addr) {
        Script::Comment::CommentInfo c{};
        Script::Comment::GetInfo(addr, &c);
        return nlohmann::json() = dbgUtils::COMMENT_INFO_WRAPPER{
            c.mod,
            c.rva,
            c.text,
            c.manual
        };
    }

	auto Set(ptr_t addr, const std::string& text, bool manual) {
		return Script::Comment::Set(addr, text.c_str(), manual);
	}

	auto Del(ptr_t addr) {
		return Script::Comment::Delete(addr);
	}
};

namespace x64dbgSvrWrapper::dbgLabel {
    auto GetLabelList() {
        nlohmann::json labels;

        BridgeList<Script::Label::LabelInfo> list;

        Script::Label::GetList(&list);

        for (int i = 0; i < list.Count(); i++) {
            labels[i] = dbgUtils::LABEL_INFO_WRAPPER{
                list[i].mod,
                list[i].rva,
                list[i].text,
                list[i].manual
            };
        } return labels;
    }

    auto Get(ptr_t addr) {
        Script::Label::LabelInfo l{};
        Script::Label::GetInfo(addr, &l);
        return nlohmann::json() = dbgUtils::LABEL_INFO_WRAPPER{
            l.mod,
            l.rva,
            l.text,
            l.manual
        };
    }

    auto Set(ptr_t addr, const std::string& text, bool manual, bool temporary) {
        return Script::Label::Set(addr, text.c_str(), manual, temporary);
    }

    auto Del(ptr_t addr) {
        return Script::Label::Delete(addr);
    }

	auto IsTemporary(ptr_t addr) {
		return Script::Label::IsTemporary(addr);
	}

	auto FromString(const std::string& label) {
		duint addr = 0;
        return ptr_t(Script::Label::FromString(label.c_str(), &addr) ? addr : 0);
    }
};

namespace x64dbgSvrWrapper::dbgFunction {
    auto GetFunctionList() {
        nlohmann::json functions;

        BridgeList<Script::Function::FunctionInfo> list;

        Script::Function::GetList(&list);

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

	auto Get(ptr_t addr) {
		Script::Function::FunctionInfo f{};
		Script::Function::GetInfo(addr, &f);
		return nlohmann::json() = dbgUtils::FUNCTION_INFO_WRAPPER{
			f.mod,
			f.rvaStart,
			f.rvaEnd,
			f.manual,
			f.instructioncount
		};
	}

	auto Add(ptr_t start, ptr_t end, bool manual, size_t instructionCount) {
		return Script::Function::Add(start, end, manual, instructionCount);
	}

	auto Del(ptr_t addr) {
		return Script::Function::Delete(addr);
	}
};

namespace x64dbgSvrWrapper::dbgArgument {
    auto GetArgumentList() {
        nlohmann::json arguments;

        BridgeList<Script::Argument::ArgumentInfo> list;

        Script::Argument::GetList(&list);

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

    auto Get(ptr_t addr) {
        Script::Argument::ArgumentInfo a{};
        Script::Argument::GetInfo(addr, &a);
        return nlohmann::json() = dbgUtils::ARGUMENT_INFO_WRAPPER{
            a.mod,
            a.rvaStart,
            a.rvaEnd,
            a.manual,
            a.instructioncount
        };
    }

	auto Add(ptr_t addr, ptr_t end, bool manual, size_t instructionCount) {
		return Script::Argument::Add(addr, end, manual, instructionCount);
	}

	auto Del(ptr_t addr) {
		return Script::Argument::Delete(addr);
	}
};

namespace x64dbgSvrWrapper::dbgXref {
    auto Get(ptr_t addr) {
        nlohmann::json references;

        XREF_INFO xref{};

        DbgXrefGet(addr, &xref);

        for (size_t i = 0; i < xref.refcount; i++) {
            references[i] = dbgUtils::XREF_RECORD_WRAPPER{
                xref.references[i].addr,
                xref.references[i].type
            };
        }

        if (xref.references) BridgeFree(xref.references);

        return nlohmann::json() = dbgUtils::XREF_INFO_WRAPPER{
            xref.refcount,
            references,
        };
    }
	auto Add(ptr_t addr, ptr_t from) {
		return DbgXrefAdd(addr, from);
	}
	auto DelAll(ptr_t addr) {
		return DbgXrefDelAll(addr);
	}
    auto GetCountAt(ptr_t addr) {
        return DbgGetXrefCountAt(addr);
    }
    auto GetTypeAt(ptr_t addr) {
        return DbgGetXrefTypeAt(addr);
    }
};

namespace x64dbgSvrWrapper::dbgScript {
	auto Load(const std::string& filename) {
		DbgScriptLoad(filename.c_str());
		return nlohmann::json();
	}
	auto Unload() {
		DbgScriptUnload();
		return nlohmann::json();
	}
	auto Run(int destline) {
		DbgScriptRun(destline);
		return nlohmann::json();
	}
	auto Abort() {
		DbgScriptAbort();
		return nlohmann::json();
	}
	auto CmdExec(const std::string& command) {
		DbgScriptCmdExec(command.c_str());
		return nlohmann::json();
	}
};

namespace x64dbgSvrWrapper::dbgBreakpoint {
    auto GetBreakpointList(int32_t bpxtype) {
        nlohmann::json breaks;

        BPMAP bps{};
        DbgGetBpList(BPXTYPE(bpxtype), &bps);

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

namespace x64dbgSvrWrapper::dbgModule {
    auto GetModuleList() {
        nlohmann::json modules;

        BridgeList<Script::Module::ModuleInfo> list;

        Script::Module::GetList(&list);

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

        Script::Module::GetMainModuleSectionList(&list);

        for (int i = 0; i < list.Count(); i++) {
            sections[i] = dbgUtils::MODULE_SECTION_INFO_WRAPPER{
                list[i].addr, list[i].size, list[i].name
            };
        } return sections;
    }

    auto SectionListFromAddr(ptr_t addr) {
        nlohmann::json sections;

        BridgeList<Script::Module::ModuleSectionInfo> list;

        Script::Module::SectionListFromAddr(addr, &list);

        for (int i = 0; i < list.Count(); i++) {
            sections[i] = dbgUtils::MODULE_SECTION_INFO_WRAPPER{
                list[i].addr, list[i].size, list[i].name
            };
        } return sections;
    }

    auto SectionListFromName(const std::string& n) {
        nlohmann::json sections;

        BridgeList<Script::Module::ModuleSectionInfo> list;

        Script::Module::SectionListFromName(n.c_str(), &list);

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

        Script::Module::GetExports(&m, &list);

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

        Script::Module::GetImports(&m, &list);

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
            threads[i] = dbgUtils::THREAD_ALL_INFO_WRAPPER{
				dbgUtils::THREAD_INFO_WRAPPER{
					list.list[i].BasicInfo.ThreadNumber,
					ptr_t(list.list[i].BasicInfo.Handle),
					list.list[i].BasicInfo.ThreadId,
					list.list[i].BasicInfo.ThreadStartAddress,
					list.list[i].BasicInfo.ThreadLocalBase,
					list.list[i].BasicInfo.threadName
				},
				list.list[i].ThreadCip,
				list.list[i].SuspendCount,
				list.list[i].Priority,
				list.list[i].WaitReason,
				list.list[i].LastError,
				dbgUtils::FILETIME_WRAPPER{
					list.list[i].UserTime.dwLowDateTime,
					list.list[i].UserTime.dwHighDateTime
				},
				dbgUtils::FILETIME_WRAPPER{
					list.list[i].KernelTime.dwLowDateTime,
					list.list[i].KernelTime.dwHighDateTime
				},
				dbgUtils::FILETIME_WRAPPER{
					list.list[i].CreationTime.dwLowDateTime,
					list.list[i].CreationTime.dwHighDateTime
				},
				list.list[i].Cycles,
            };
        }
        BridgeFree(list.list); return threads;
    }

    auto GetFirstThreadId() {
        for (const auto& t : dbgThread::GetThreadList()) {
			std::string raw = t.dump();
            if (0 == t["BasicInfo"]["ThreadNumber"]) {
                return uint32_t(t["BasicInfo"]["ThreadId"]);
            }
        }
        return uint32_t(GuiGetMainThreadId());
    }

	auto SetThreadName(uint32_t threadId, const std::string& name) {
		std::string fmtV = fmt::format("setthreadname {:x},{}", threadId, name);
		return DbgCmdExecDirect(fmtV.c_str());
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
        DbgMemMap(&maps);

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
    auto Write(ptr_t addr, const std::string& reqbuffer) {
        std::vector<uint8_t> buffer = x64dbgSvrUtil::RequestBuffer::Deserialize(reqbuffer);
        return Script::Memory::Write(addr, buffer.data(), buffer.size(), 0);
    }
    auto Read(ptr_t addr, size_t size) {
		std::vector<uint8_t> buffer(size);
        Script::Memory::Read(addr, buffer.data(), buffer.size(), 0);
        return x64dbgSvrUtil::RequestBuffer::Serialize(buffer);
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
    auto RunCommand(const std::string& cmd) {
        return DbgCmdExecDirect(cmd.c_str());
    }
    auto RunCommandAsync(const std::string& cmd) {
        return DbgCmdExec(cmd.c_str());
    }

    auto Stop() {
        RunCommandAsync("StopDebug"); //Script::Debug::Stop();
        return nlohmann::json();
    }
	auto Run() { 
        RunCommandAsync("run"); //Script::Debug::Run();
        return nlohmann::json();
    }
	auto Pause() { 
        RunCommandAsync("pause"); //Script::Debug::Pause();
        return nlohmann::json();
    }
	auto StepInto() {
        RunCommandAsync("StepInto"); //Script::Debug::StepIn();
        return nlohmann::json();
    }
	auto StepOver() { 
        RunCommandAsync("StepOver"); //Script::Debug::StepOver();
        return nlohmann::json();
    }
	auto StepOut() { 
        RunCommandAsync("StepOut"); //Script::Debug::StepOut();
        return nlohmann::json();
    }

    auto IsDebugging() {
        return DbgIsDebugging();
    }
    auto IsRunning() {
        return DbgIsRunning();
    }
};