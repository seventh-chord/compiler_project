@echo off

echo.
echo RUNNING TESTS
echo.

build\sea       src\assorted\first.sea          build\test1.exe                 -r
echo.
build\sea       src\assorted\second.sea         build\test2.exe                 -r
echo.
build\sea       src\link_test\backend.sea       src\link_test\build\out.exe     -r
echo.
build\sea       src\glfw_test\main.sea          src\glfw_test\out.exe

