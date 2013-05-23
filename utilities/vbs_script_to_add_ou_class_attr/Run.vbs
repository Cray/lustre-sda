
Dim objShell
Set objShell = Wscript.CreateObject("WScript.Shell")

objShell.Run "CreateOU.vbs" 
objShell.Run "addaclid.vbs" 
objShell.Run "addaclkey.vbs"
objShell.Run "xyGroupServerKey.vbs"

objShell.Run "addclass_xyGroupServer.vbs" 
objShell.Run "addclass_xylrpc.vbs"
objShell.Run "addclass_xyRootGroupServer.vbs"

WScript.Echo "Success: Created attributeSchema class object "


