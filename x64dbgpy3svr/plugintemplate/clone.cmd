@echo off

cd /D %~dp0

set X64TEMPLATE=https://github.com/x64dbg/PluginTemplate/

setlocal enabledelayedexpansion

set PLUGIN[0]=plugin
set PLUGIN[1]=pluginmain


:: plugintemplate
for /l %%i in (0, 1, 1) do ( curl -L %X64TEMPLATE%blob/main/src/!PLUGIN[%%i]!.h?raw=true -o !PLUGIN[%%i]!.h && curl -L %X64TEMPLATE%blob/main/src/!PLUGIN[%%i]!.cpp?raw=true -o !PLUGIN[%%i]!.cpp )


:: pluginsdk
:: https://api.github.com/repos/x64dbg/x64dbg/releases/latest
set SNAPSHOT=snapshot_2023-06-10_18-05
curl -L https://github.com/x64dbg/x64dbg/releases/download/snapshot/%SNAPSHOT%.zip -o x64dbg.zip
tar -xf x64dbg.zip pluginsdk/
del /Q x64dbg.zip