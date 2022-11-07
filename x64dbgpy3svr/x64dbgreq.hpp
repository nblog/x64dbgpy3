#pragma once

/* ??? */
#include "egg.h"


#include <cpp-httplib/httplib.h>
#include <jsonrpccxx/server.hpp>


/* x64dbg script wrapper */
#include "x64dbghandler.hpp"


/* https://github.com/jsonrpcx/json-rpc-cxx/blob/master/examples/cpphttplibconnector.hpp#L23 */
class CppHttpLibServerConnector {
public:
    explicit CppHttpLibServerConnector(int port, jsonrpccxx::JsonRpcServer& server) :
        thread(),
        server(server),
        httpServer(),
        port(port) {
        httpServer.Get("/", [=](const httplib::Request& /*req*/, httplib::Response& res) { 
#ifdef NDEBUG
            /* ??? */
            res.set_content((const char*)egg_data, sizeof(egg_data), egg_mime);
#endif
        });

        httpServer.Get("/x64dbginfo", 
            [=](const httplib::Request& /*req*/, httplib::Response& res) {
                res.set_content(nlohmann::json(
                    {
                        { "ver", PLUGIN_VERSION },
#ifdef _WIN64
                        { "x64dbg", true },
#else
                        { "x64dbg", false },
#endif
                        { "window", uintptr_t(GuiGetWindowHandle()) },

                        { "engine", int32_t(DbgGetDebugEngine()) },
                    }
                ).dump(), "application/json");
            });
        httpServer.Post("/x64dbgreq",
            [this](const httplib::Request& req, httplib::Response& res) {
                this->PostAction(req, res);
            });
    }

    virtual ~CppHttpLibServerConnector() { StopListening(); }

    bool StartListening() {
        if (httpServer.is_running())
            return false;
        this->thread = std::thread([this]() { this->httpServer.listen("localhost", port); });
        return true;
    }

    void StopListening() {
        if (httpServer.is_running()) {
            httpServer.stop();
            this->thread.join();
        }
    }

private:
    std::thread thread;
    jsonrpccxx::JsonRpcServer& server;
    httplib::Server httpServer;
    int port;

    void PostAction(const httplib::Request& req,
        httplib::Response& res) {
        res.status = 200;
        res.set_content(this->server.HandleRequest(req.body), "application/json");
    }
};






#define AddHandler(bindings, mapping) \
    x64dbgBindings().Add(#bindings, GetHandle(&##bindings), mapping)


class x64dbgSvrBindings {
    /* x64dbgSvrWrapper app_; */
    jsonrpccxx::JsonRpc2Server x64dbgBindings_;

public:
    auto& x64dbgBindings() { return x64dbgBindings_; }

    x64dbgSvrBindings() {
        using namespace jsonrpccxx;
        using namespace x64dbgSvrWrapper;

        AddHandler(dbgLogging::logclear, {  });
        AddHandler(dbgLogging::logprint, {  });
        AddHandler(dbgLogging::logputs, {  });

        AddHandler(dbgMisc::IsDebugging, {  });
        AddHandler(dbgMisc::IsRunning, {  });
        AddHandler(dbgMisc::ParseExpression, {  });
        AddHandler(dbgMisc::RemoteGetProcAddress, {  });
        AddHandler(dbgMisc::ResolveLabel, {  });

        AddHandler(dbgGui::Refresh, {  });
        AddHandler(dbgGui::Message, {  });
        AddHandler(dbgGui::MessageYesNo, {  });
        AddHandler(dbgGui::FocusView, {  });
        AddHandler(dbgGui::SelectionSet, {  });
        AddHandler(dbgGui::SelectionGet, {  });

        AddHandler(dbgPattern::FindPattern, {  });

        AddHandler(dbgAssembler::Assemble, {  });
        AddHandler(dbgAssembler::DisasmFast, {  });

        AddHandler(dbgSymbol::GetSymbolList, {  });

        AddHandler(dbgBookmark::GetBookmarkList, {  });

        AddHandler(dbgComment::GetCommentList, {  });

        AddHandler(dbgLabel::GetLabelList, {  });

        AddHandler(dbgFunction::GetFunctionList, {  });

        AddHandler(dbgArgument::GetArgumentList, {  });

        AddHandler(dbgModule::GetModuleList, {  });
        AddHandler(dbgModule::GetMainModuleInfo, {  });
        AddHandler(dbgModule::InfoFromAddr, {  });
        AddHandler(dbgModule::InfoFromName, {  });
        AddHandler(dbgModule::GetMainModuleSectionList, {  });
        AddHandler(dbgModule::SectionListFromAddr, {  });
        AddHandler(dbgModule::SectionListFromName, {  });
        AddHandler(dbgModule::GetExportsFromAddr, {  });
        AddHandler(dbgModule::GetImportsFromAddr, {  });

        AddHandler(dbgThread::GetThreadList, {  });
        AddHandler(dbgThread::GetFirstThreadId, {  });
        AddHandler(dbgThread::GetActiveThreadId, {  });
        AddHandler(dbgThread::SetActiveThreadId, {  });
        AddHandler(dbgThread::SuspendThreadId, {  });
        AddHandler(dbgThread::ResumeThreadId, {  });
        AddHandler(dbgThread::KillThread, {  });
        AddHandler(dbgThread::CreateThread, {  });

        AddHandler(dbgProcess::ProcessId, {  });
        AddHandler(dbgProcess::NativeHandle, {  });

        AddHandler(dbgMemory::MemMaps, {  });
        AddHandler(dbgMemory::ValidPtr, {  });
        AddHandler(dbgMemory::Read, {  });
        AddHandler(dbgMemory::Write, {  });
        AddHandler(dbgMemory::Free, {  });
        AddHandler(dbgMemory::Alloc, {  });
        AddHandler(dbgMemory::Base, {  });
        AddHandler(dbgMemory::Size, {  });

        AddHandler(dbgStack::Pop, {  });
        AddHandler(dbgStack::Push, {  });

        AddHandler(dbgRegister::GetFlag, {  });
        AddHandler(dbgRegister::SetFlag, {  });
        AddHandler(dbgRegister::GetRegister, {  });
        AddHandler(dbgRegister::SetRegister, {  });

        AddHandler(dbgDebug::Stop, {  });
        AddHandler(dbgDebug::Run, {  });
        AddHandler(dbgDebug::StepIn, {  });
        AddHandler(dbgDebug::StepOver, {  });
        AddHandler(dbgDebug::StepOut, {  });

        AddHandler(dbgDebug::GetBreakpointList, {  });
        AddHandler(dbgDebug::SetBreakpoint, {  });
        AddHandler(dbgDebug::DeleteBreakpoint, {  });
        AddHandler(dbgDebug::DisableBreakpoint, {  });

        AddHandler(dbgDebug::SetHardwareBreakpoint, {  });
        AddHandler(dbgDebug::DeleteHardwareBreakpoint, {  });
    };
};

#undef AddHandler