
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN

#include "plugin.h"

#include "x64dbgreq.hpp"

#define DEFAULT_PORT 27041


enum enum_menu_entry {
    MENU_ABOUT = 20221102,
    MENU_STARTSVR,
};


struct httpsvr: public CppHttpLibServerConnector {
    httpsvr(int port) : CppHttpLibServerConnector(port, x64dbg.x64dbgBindings()) {

    };

    static inline void clear(void* self) { 
        if (self) { ((httpsvr*)self)->StopListening(); delete self; }
    }
private:
    x64dbgSvrBindings x64dbg;
}; httpsvr *svr = nullptr;



static bool start_httpsvr(int argc, char* argv[])
{
    int port = 2 > argc ? DEFAULT_PORT : int(strtoul(argv[1], 0, 0));

    httpsvr::clear(svr);

    svr = new httpsvr(port);
    bool isOk = svr->StartListening();

    if (isOk)
        x64dbgSvrWrapper::dbgLogging::logputs(
            fmt::format("HTTP server started successfully, port:{}", port)); 
    else
        x64dbgSvrWrapper::dbgLogging::logputs(
            fmt::format("HTTP server failed to start", port));

    return isOk;
}



//Initialize your plugin data here.
bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
    if (!_plugin_registercommand(pluginHandle, PLUGIN_NAME, start_httpsvr, false))
        _plugin_logputs("[" PLUGIN_NAME "] Error registering the '" PLUGIN_NAME "' command!");

    return true; //Return false to cancel loading the plugin.
}

//Deinitialize your plugin data here.
void pluginStop()
{
    httpsvr::clear(svr);
}

//Do GUI/Menu related things here.
void pluginSetup()
{
    _plugin_menuaddentry(hMenu, MENU_ABOUT, "&About");
}



PLUG_EXPORT void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY* info)
{
    switch (info->hEntry)
    {
    case MENU_STARTSVR: {

    } break;
    case MENU_ABOUT: {
        Script::Gui::Message("Hi");
    } break;
    default:
        break;
    }
}
