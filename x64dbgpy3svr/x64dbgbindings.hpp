#pragma once

/* ??? */
#include "egg.h"

#include <cpp-httplib/httplib.h>
#include <jsonrpccxx/server.hpp>

/* x64dbg interface wrapper */
#include "x64dbghandler.hpp"


/* https://github.com/jsonrpcx/json-rpc-cxx/blob/master/examples/cpphttplibconnector.hpp#L23 */
class CppHttpLibServerConnector {
public:
    ~CppHttpLibServerConnector() { this->StopListening(); }

    explicit CppHttpLibServerConnector(jsonrpccxx::JsonRpcServer& server, int port, std::string host="localhost") :
        server_(server),
        port_(port),
        host_(host) {
        this->http_server_.Get("/", [=](const httplib::Request& /*req*/, httplib::Response& res) { 
#ifndef NDEBUG
            res.status = 200;
            res.set_content("Hi!", "text/plain");
#else
            /* ??? */
            res.status = 200;
            res.set_content((const char*)egg_data, sizeof(egg_data), egg_mime);
#endif
        });

        this->http_server_.Get("/x64dbg/api/info", 
            [=](const httplib::Request& /*req*/, httplib::Response& res) {
                try
                {
                    res.set_content(nlohmann::json({
                        { "plugin", fmt::format("{}.{}.{}", ((PLUGIN_VERSION >> 16) & 0xFF), ((PLUGIN_VERSION >> 8) & 0xFF), (PLUGIN_VERSION & 0xFF)) },
#ifdef _WIN64
                        { "x64dbg", true },
#else
                        { "x64dbg", false },
#endif
                        { "x64dbg_hwnd", uintptr_t(GuiGetWindowHandle()) },
                        { "x64dbg_dir", BridgeUserDirectory() },
                        }).dump(), "application/json");
                }
                catch (const std::exception& e)
                {
                    res.status = 500;
                    res.set_content(nlohmann::json({
                        { "error", e.what() }
                        }).dump(), "application/json");
                }
            });
        this->http_server_.Post("/x64dbg/api/call",
            [this](const httplib::Request& req, httplib::Response& res) {
                try {
                    this->PostAction(req, res);
                }
                catch (const std::exception& e) {
                    res.status = 500;
                    res.set_content(nlohmann::json({
                        { "error", e.what() }
                        }).dump(), "application/json");
                }
            });
    }

    bool StartListening() noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        if (this->http_server_.is_running())
            return false;

        this->thread_ = std::make_unique<std::thread>([this]() { 
            this->http_server_.listen(this->host_.c_str(), this->port_); });
        return this->thread_ ? true : false;
    }

    void StopListening() noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        if (this->thread_ && this->http_server_.is_running()) {
            this->http_server_.stop();
            this->thread_->join();
            this->thread_.reset();
        }
    }

private:
    std::string host_; int port_;
    std::unique_ptr<std::thread> thread_;
    std::mutex mutex_;
	jsonrpccxx::JsonRpcServer& server_;
    httplib::Server http_server_;

    void PostAction(const httplib::Request& req,
        httplib::Response& res) {
        const std::string& response = this->server_.HandleRequest(req.body);
        res.status = 200;
        res.set_content(response, "application/json");
    }
};


#pragma push_macro("AddHandler")
#undef AddHandler
#define AddHandler(bindings, mapping) \
       x64dbgBindings().Add(#bindings, GetHandle(&bindings), mapping)

class X64DbgServerBindings {
    /* x64dbgSvrWrapper app_; */
    jsonrpccxx::JsonRpc2Server x64dbgBindings_;

public:
    auto& x64dbgBindings() noexcept { return x64dbgBindings_; }

    X64DbgServerBindings() {
        using namespace jsonrpccxx;
        using namespace x64dbgSvrWrapper;

        AddHandler(dbgLogging::logclear, {  });
        AddHandler(dbgLogging::logputs, {  });
        AddHandler(dbgLogging::logprint, {  });

        AddHandler(dbgMisc::IsDebugging, {  });
        AddHandler(dbgMisc::IsRunning, {  });
		AddHandler(dbgMisc::GetLabelAt, {  });
		AddHandler(dbgMisc::GetCommentAt, {  });
		AddHandler(dbgMisc::GetStringAt, {  });
		AddHandler(dbgMisc::GetWatchList, {  });
        AddHandler(dbgMisc::ParseExpression, {  });
        AddHandler(dbgMisc::ResolveLabel, {  });
        AddHandler(dbgMisc::RemoteGetProcAddress, {  });

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
		AddHandler(dbgBookmark::Get, {  });
		AddHandler(dbgBookmark::Set, {  });
		AddHandler(dbgBookmark::Del, {  });

        AddHandler(dbgComment::GetCommentList, {  });
		AddHandler(dbgComment::Get, {  });
		AddHandler(dbgComment::Set, {  });
		AddHandler(dbgComment::Del, {  });

        AddHandler(dbgLabel::GetLabelList, {  });
		AddHandler(dbgLabel::Get, {  });
        AddHandler(dbgLabel::Set, {  });
        AddHandler(dbgLabel::Del, {  });
        AddHandler(dbgLabel::IsTemporary, {  });
        AddHandler(dbgLabel::FromString, {  });

        AddHandler(dbgFunction::GetFunctionList, {  });
		AddHandler(dbgFunction::Get, {  });
		AddHandler(dbgFunction::Add, {  });
		AddHandler(dbgFunction::Del, {  });

        AddHandler(dbgArgument::GetArgumentList, {  });
		AddHandler(dbgArgument::Get, {  });
		AddHandler(dbgArgument::Add, {  });
		AddHandler(dbgArgument::Del, {  });

        AddHandler(dbgXref::Get, {  });
        AddHandler(dbgXref::Add, {  });
        AddHandler(dbgXref::DelAll, {  });
        AddHandler(dbgXref::GetCountAt, {  });
        AddHandler(dbgXref::GetTypeAt, {  });

		AddHandler(dbgScript::Load, {  });
        AddHandler(dbgScript::Unload, {  });
		AddHandler(dbgScript::Run, {  });
		AddHandler(dbgScript::Abort, {  });
		AddHandler(dbgScript::CmdExec, {  });

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
        AddHandler(dbgMemory::Free, {  });
        AddHandler(dbgMemory::Alloc, {  });
        AddHandler(dbgMemory::Base, {  });
        AddHandler(dbgMemory::Size, {  });
        AddHandler(dbgMemory::Write, {  });
        AddHandler(dbgMemory::Read, {  });

        AddHandler(dbgStack::Pop, {  });
        AddHandler(dbgStack::Push, {  });

        AddHandler(dbgRegister::GetFlag, {  });
        AddHandler(dbgRegister::SetFlag, {  });
        AddHandler(dbgRegister::GetRegister, {  });
        AddHandler(dbgRegister::SetRegister, {  });

        AddHandler(dbgDebug::Stop, {  });
		AddHandler(dbgDebug::Pause, {  });
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

#pragma pop_macro("AddHandler")