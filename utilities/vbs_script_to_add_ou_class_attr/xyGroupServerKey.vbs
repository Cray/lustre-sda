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

' Declarations for new attribute.
Const strAttributeName = "xyGroupServerKey"  ' Attribute name.
Dim objNewAttribute                                ' New attribute.
Dim strCNAttributeName                             ' Attribute CN.

' Create new attribute.
strCNAttributeName = "CN=" & strAttributeName
Set objNewAttribute = objSchema.Create("attributeSchema", _
                          strCNAttributeName)

' Set selected values for attribute.
objNewAttribute.Put "instanceType", DS_INSTANCETYPE_NC_IS_WRITEABLE
objNewAttribute.Put "attributeID", "1.2.840.113556.1.8000.2554.999999.2.3"
objNewAttribute.Put "attributeSyntax", "2.5.5.3"
objNewAttribute.Put "isSingleValued", True
objNewAttribute.Put "rangeUpper", 32768
objNewAttribute.Put "showInAdvancedViewOnly", True
objNewAttribute.Put "adminDisplayName", strAttributeName
objNewAttribute.Put "adminDescription", "Group Server Key "
objNewAttribute.Put "oMSyntax", 27
objNewAttribute.Put "searchFlags", 0
objNewAttribute.Put "lDAPDisplayName", "xyGroupServerKey"
objNewAttribute.Put "name", strAttributeName
objNewAttribute.Put "systemOnly", False
objNewAttribute.Put "systemFlags", 16
objNewAttribute.Put "objectCategory", "CN=Attribute-Schema," & _
                        strSchemaNamingContext
objNewAttribute.SetInfo
WScript.Echo "Success: Created attributeSchema class object: " & _
                 objNewAttribute.Name

' Update schema cache.
WScript.Echo "         Updating the schema cache."
objRoot.Put "schemaUpdateNow", 1
objRoot.SetInfo
WScript.Echo

