@echo OFF

if not exist build mkdir build

set DEBUG_VAR="NODEBUG"
if "%1"=="debug" set DEBUG_VAR="DEBUG"

cl /nologo /c /WX^
    /GS- /Gs9999999^
    /Od^
    /Zi^
    /Fd"build\main.pdb"^
    /Fo"build\main.obj"^
    /TC^
    /D%DEBUG_VAR%^
    /D"WINDOWS"^
    "compiler.c"^
 &&^
link /nologo^
    /nodefaultlib /subsystem:console^
    /stack:0x100000,0x100000^
    /debug^
    /incremental:no^
    /entry:program_entry^
    /out:"build\sea.exe"^
    build\main.obj kernel32.lib^
