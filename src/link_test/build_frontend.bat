@echo off

if not exist build mkdir build
 
cl   /nologo /c /Fo"build\frontend.obj" "frontend.c"
lib  /nologo /OUT:"build\frontend.lib" "build\frontend.obj"
link /nologo /noentry /dll /OUT:"build\frontend.dll" "build\frontend.obj"
