@echo OFF

if not exist build mkdir build

cl /nologo /c^
    /GS- /Gs9999999^
    /Od^
    /Zi^
    /Fd"build\tiny.pdb"^
    /Fo"build\tiny.obj"^
    tiny.c^
 &&^
link /nologo^
    /nodefaultlib /subsystem:console^
    /stack:0x100000,0x100000^
    /debug^
    /incremental:no^
    /entry:main^
    /out:"build\tiny.exe"^
    build\tiny.obj kernel32.lib^
 &&^
build\tiny.exe

cl /nologo /c^
    /GS- /Gs9999999^
    /Od^
    /Zi^
    /Fd"build\main.pdb"^
    /Fo"build\main.obj"^
    /TC^
    "main.c"^
 &&^
link /nologo^
    /nodefaultlib /subsystem:console^
    /stack:0x100000,0x100000^
    /debug^
    /incremental:no^
    /entry:program_entry^
    /out:"build\program.exe"^
    build\main.obj kernel32.lib^
 &&^
build\program.exe
