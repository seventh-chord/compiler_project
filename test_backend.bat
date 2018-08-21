@echo OFF

if not exist build mkdir build

cl /nologo /c /WX^
    /GS- /Gs9999999^
    /Od^
    /Zi^
    /Fd"build\backend.pdb"^
    /Fo"build\backend.obj"^
    /TC^
    /D"DEBUG"^
    /D"WINDOWS"^
    "backend.c"^
 &&^
link /nologo^
    /nodefaultlib /subsystem:console^
    /stack:0x100000,0x100000^
    /debug^
    /incremental:no^
    /entry:program_entry^
    /out:"build\backend.exe"^
    build\backend.obj kernel32.lib^
 &&^
build\backend.exe
