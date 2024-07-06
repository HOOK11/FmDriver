set "proProjectpath=%cd%"

cd ../

set "preProjectpath=%cd%"

cd %proProjectpath%

set "SignSysPath=%preProjectpath%/x64/Release/DriverLoad.sys.vmp"

set "SignPath=%preProjectpath%/x64/Release/DriverLoad.vmp.sys"

"E:\VMProtect\VMProtect_Con.exe" %SignSysPath%

"E:\DSignTool\this\CSignTool.exe"  sign /r 22 /f %SignPath% /ac

copy "F:\windowsDriver\FmDriver-master\x64\Release\DriverLoad.vmp.sys" "F:\windowsDriver\FmDriver-master\x64\Release\FM.sys"

