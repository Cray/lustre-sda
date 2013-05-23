' Extend AD LDS Schema with the Contact Class
' and Additional-Information Attribute.

Option Explicit

' Global declarations.
Const ADS_PROPERTY_APPEND             = 3  ' Append operation.
Const DS_INSTANCETYPE_NC_IS_WRITEABLE = 4  ' Write-able attribute.
Dim objRoot                 ' Root of AD LDS instance.
Dim objSchema               ' Schema partiton.
Dim strSchemaNamingContext  ' Schema DN.

' Get schema path.
Set objRoot = GetObject("LDAP://localhost:389/RootDSE")
strSchemaNamingContext = objRoot.Get("schemaNamingContext")
Set objSchema = GetObject("LDAP://localhost:389/" & _
                    strSchemaNamingContext)

WScript.Echo "Schema path: " & objSchema.ADsPath
WScript.Echo

' Declarations for new class.
Const strClassName = "xylrpc"  ' Class name.
Dim objNewClass                 ' New class.
Dim strCNClassName              ' Class CN.

' Create new class.
strCNClassName = "CN=" & strClassName
Set objNewClass = objSchema.Create("classSchema", strCNClassName)

' Set selected values for class.
objNewClass.Put "instanceType", DS_INSTANCETYPE_NC_IS_WRITEABLE
objNewClass.Put "subClassOf", "top"
objNewClass.Put "governsID", "1.2.840.113556.1.8000.2554.999999.1.1"
objNewClass.Put "rDNAttID", "cn"
objNewClass.Put "showInAdvancedViewOnly", True
objNewClass.Put "adminDisplayName", strClassName
objNewClass.Put "adminDescription", "xyratex lrpc class"
objNewClass.Put "objectClassCategory", 1
objNewClass.Put "lDAPDisplayName", strClassName
objNewClass.Put "name", strClassName
objNewClass.Put "systemOnly", False
objNewClass.PutEx ADS_PROPERTY_APPEND, _
                "systemPossSuperiors", Array("organizationalUnit", _
                "domainDNS")
objNewClass.Put "systemMayContain", _
				Array("memberUid", "xyGroupServerKey")
objNewClass.Put "systemMustContain", _ 
				Array("aclid" , "aclkey") 
objNewClass.Put "defaultSecurityDescriptor", _
                "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)" & _
                "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)" & _
                "(A;;RPLCLORC;;;AU)"
objNewClass.Put "systemFlags", 16
objNewClass.Put "defaultHidingValue", False
objNewClass.Put "objectCategory", "CN=Class-Schema," & _
                    strSchemaNamingContext
objNewClass.Put "defaultObjectCategory", "CN=xylrpc," & _
                    strSchemaNamingContext
objNewClass.SetInfo
WScript.Echo "Success: Created classSchema class object: " _
              & objNewClass.Name

' Update schema cache.
WScript.Echo "         Updating the schema cache."
objRoot.Put "schemaUpdateNow", 1
objRoot.SetInfo