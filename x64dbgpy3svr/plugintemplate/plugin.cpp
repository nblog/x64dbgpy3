
#ifdef _WIN64
#pragma comment(lib, "pluginsdk/x64dbg.lib")
#pragma comment(lib, "pluginsdk/x64bridge.lib")
// #pragma comment(lib, "pluginsdk/dbghelp/dbghelp_x64.lib")
// #pragma comment(lib, "pluginsdk/DeviceNameResolver/DeviceNameResolver_x64.lib")
// #pragma comment(lib, "pluginsdk/jansson/jansson_x64.lib")
// #pragma comment(lib, "pluginsdk/lz4/lz4_x64.lib")
// #pragma comment(lib, "pluginsdk/TitanEngine/TitanEngine_x64.lib")
// #pragma comment(lib, "pluginsdk/XEDParse/XEDParse_x64.lib")
#else
#pragma comment(lib, "pluginsdk/x32dbg.lib")
#pragma comment(lib, "pluginsdk/x32bridge.lib")
// #pragma comment(lib, "pluginsdk/dbghelp/dbghelp_x86.lib")
// #pragma comment(lib, "pluginsdk/DeviceNameResolver/DeviceNameResolver_x86.lib")
// #pragma comment(lib, "pluginsdk/jansson/jansson_x86.lib")
// #pragma comment(lib, "pluginsdk/lz4/lz4_x86.lib")
// #pragma comment(lib, "pluginsdk/TitanEngine/TitanEngine_x86.lib")
// #pragma comment(lib, "pluginsdk/XEDParse/XEDParse_x86.lib")
#endif

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include "plugin.h"
#include <x64dbgbindings.hpp>

#define PLUGIN_NAME "x64dbgpy3svr"
#define PLUGIN_VERSION 0x010102 // 1.1.2

// Examples: https://github.com/x64dbg/x64dbg/wiki/Plugins
// References:
// - https://help.x64dbg.com/en/latest/developers/plugins/index.html
// - https://x64dbg.com/blog/2016/10/04/architecture-of-x64dbg.html
// - https://x64dbg.com/blog/2016/10/20/threading-model.html
// - https://x64dbg.com/blog/2016/07/30/x64dbg-plugin-sdk.html

struct HttpServer : public CppHttpLibServerConnector
{
    HttpServer(int port, std::string host)
        : CppHttpLibServerConnector(this->x64dbg_.x64dbgBindings(), port, host)
    {
    }

public:
    static inline void clear(std::optional<HttpServer> &self)
    {
        if (self)
            self.reset();
    }

private:
    X64DbgServerBindings x64dbg_;
};
std::optional<HttpServer> svr;

enum X64DBGPY3MENUMENTRY
{
    X64DBG_ABOUT = 20250501,
    X64DBG_STARTSVR,
};

#define X64DBGPY3_DEFAULT_HOST "0.0.0.0"
#define X64DBGPY3_DEFAULT_PORT 27041

//
PLUG_EXPORT void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY *info)
{
    switch (info->hEntry)
    {
    case X64DBGPY3MENUMENTRY::X64DBG_ABOUT:
    {
        x64dbgSvrWrapper::rtcmsgbox(x64dbgSvrWrapper::format("Hi"));
    }
    break;
    case X64DBGPY3MENUMENTRY::X64DBG_STARTSVR:
    {
    }
    break;
    default:
        break;
    }
}

// Command use the same signature as main in C
// argv[0] contains the full command, after that are the arguments
// NOTE: arguments are separated by a COMMA (not space like WinDbg)
static bool cbExampleCommand(int argc, char **argv)
{
    int server_port = X64DBGPY3_DEFAULT_PORT;
    if (argc > 2)
    {
        char *endptr;
        errno = 0;
        long port = strtol(argv[1], &endptr, 10);
        if (errno == 0 && endptr != argv[1] && *endptr == '\0' &&
            port > 0 && port <= 65535)
        {
            server_port = static_cast<int>(port);
        }
        else
        {
            dprintf("Invalid port number, using default %d\n", X64DBGPY3_DEFAULT_PORT);
        }
    }

    std::string server_host = 3 > argc ? X64DBGPY3_DEFAULT_HOST : argv[2];

    HttpServer::clear(svr);
    svr.emplace(server_port, server_host);

    bool isOk = svr->StartListening();
    if (isOk)
    {
        dprintf("Server started on %s:%d\n", server_host.c_str(), server_port);
    }
    else
    {
        dprintf("Failed to start server on %s:%d\n", server_host.c_str(), server_port);
    }

    return isOk;
}

// Initialize your plugin data here.
bool pluginInit(PLUG_INITSTRUCT *initStruct)
{
    dprintf("pluginInit(pluginHandle: %d)\n", pluginHandle);

    // Prefix of the functions to call here: _plugin_register
    _plugin_registercommand(pluginHandle, PLUGIN_NAME, cbExampleCommand, true);

    // Return false to cancel loading the plugin.
    return true;
}

// Deinitialize your plugin data here.
// NOTE: you are responsible for gracefully closing your GUI
// This function is not executed on the GUI thread, so you might need
// to use WaitForSingleObject or similar to wait for everything to close.
void pluginStop()
{
    // Prefix of the functions to call here: _plugin_unregister

    dprintf("pluginStop(pluginHandle: %d)\n", pluginHandle);

    // Stop the server if it is running
    HttpServer::clear(svr);
}

// Do GUI/Menu related things here.
// This code runs on the GUI thread: GetCurrentThreadId() == GuiGetMainThreadId()
// You can get the HWND using GuiGetWindowHandle()
void pluginSetup()
{
    // Prefix of the functions to call here: _plugin_menu

    dprintf("pluginSetup(pluginHandle: %d)\n", pluginHandle);

    // auto icon = x64dbg::icon();
    // ICONDATA icondata{ icon.data(), icon.size() };
    // _plugin_menuseticon(hMenu, &icondata);
    _plugin_menuaddentry(hMenu, X64DBGPY3MENUMENTRY::X64DBG_ABOUT, "&About");
}
