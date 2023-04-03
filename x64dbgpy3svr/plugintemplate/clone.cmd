@echo off


cd %~dp0


set GHPROXY=https://ghproxy.com/
set GIT=%GHPROXY%https://github.com/x64dbg/PluginTemplate/

setlocal enabledelayedexpansion

set PLUGIN[0]=plugin
set PLUGIN[1]=pluginmain


:: plugintemplate
for /l %%i in (0, 1, 1) do ( curl -L %GIT%blob/main/src/!PLUGIN[%%i]!.h?raw=true -o !PLUGIN[%%i]!.h && curl -L %GIT%blob/main/src/!PLUGIN[%%i]!.cpp?raw=true -o !PLUGIN[%%i]!.cpp )


:: pluginsdk
curl %GHPROXY%https://github.com/x64dbg/x64dbg/releases/download/snapshot/snapshot_2023-03-04_02-26.zip -o x64dbg.zip
tar -zxvf x64dbg.zip pluginsdk/
del /Q x64dbg.zip