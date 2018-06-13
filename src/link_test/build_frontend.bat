@echo off

if not exist build mkdir build
 
cl   /nologo /c /Fo"build\frontend.obj" "frontend.c"
link /nologo /noentry /dll /IMPLIB:"build\frontend.lib" /OUT:"build\frontend.dll" "build\frontend.obj"
