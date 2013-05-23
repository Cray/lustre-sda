

 
Set objDomain = GetObject("LDAP://dc=fsg1,dc=com")
Set objOU = objDomain.Create("organizationalUnit", "ou=DipsEnterprise")
hr=objOU.SetInfo  






' Extend AD LDS Schema with the Contact Class
' and Additional-Information Attribute.

Option Explicit

' Global declarations.
Const ADS_PROPERTY_APPEND             = 3  ' Append operation.
Const DS_INSTANCETYPE_NC_IS_WRITEABLE = 4  ' Write-able attribute.
Dim objRoot                 ' Root of AD LDS instance.
Dim objSchema               ' Schema partiton.
Dim strSchemaNamingContext  ' Schema DN.

Dim objDomain
Dim objOU
' Get schema path.
Set objDomain = GetObject("LDAP://dc=fsg1,dc=com")
Set objOU = objDomain.Create("organizationalUnit", "ou=xyratex")
objOU.SetInfo
WScript.Echo "Success: Created OU: " & _
                 objOU.Name
				 
Set objRoot = GetObject("LDAP://localhost:389/RootDSE")
strSchemaNamingContext = objRoot.Get("schemaNamingContext")
Set objSchema = GetObject("LDAP://localhost:389/" & _
                    strSchemaNamingContext)

WScript.Echo "Schema path: " & objSchema.ADsPath
WScript.Echo

' Declarations for new attribute. - XyGroupServerKey
Const strAttributeName = "XyGroupServerKey"  ' Attribute name.
Dim objNewAttribute                                ' New attribute.
Dim strCNAttributeName                             ' Attribute CN.

' Create new attribute.
strCNAttributeName = "CN=" & strAttributeName
Set objNewAttribute = objSchema.Create("attributeSchema", _
                          strCNAttributeName)

' Set selected values for attribute.
objNewAttribute.Put "instanceType", DS_INSTANCETYPE_NC_IS_WRITEABLE
objNewAttribute.Put "attributeID", "1.2.840.113556.1.8000.2664.88889999.2.1"
objNewAttribute.Put "attributeSyntax", "2.5.5.3"
objNewAttribute.Put "isSingleValued", True
objNewAttribute.Put "rangeUpper", 32768
objNewAttribute.Put "showInAdvancedViewOnly", True
objNewAttribute.Put "adminDisplayName", strAttributeName
objNewAttribute.Put "adminDescription", "Group Server Key"
objNewAttribute.Put "oMSyntax", 64
objNewAttribute.Put "searchFlags", 0
objNewAttribute.Put "lDAPDisplayName", "XyGroupServerKey"
objNewAttribute.Put "name", strAttributeName
objNewAttribute.Put "systemOnly", False
objNewAttribute.Put "systemFlags", 16
objNewAttribute.Put "objectCategory", "CN=Attribute-Schema," & _
                        strSchemaNamingContext
objNewAttribute.SetInfo
WScript.Echo "Success: Created attributeSchema class object: " & _
                 objNewAttribute.Name


' Declarations for new attribute. - aclid 
Const strAttributeName1 = "aclid"  				   ' Attribute name.
Dim objNewAttribute1                                ' New attribute.
Dim strCNAttributeName1                             ' Attribute CN.

' Create new attribute.
strCNAttributeName1 = "CN=" & strAttributeName1
Set objNewAttribute1 = objSchema.Create("attributeSchema", _
                          strCNAttributeName1)

' Set selected values for attribute.
objNewAttribute1.Put "instanceType", DS_INSTANCETYPE_NC_IS_WRITEABLE
objNewAttribute1.Put "attributeID", "1.2.840.113556.1.8000.2664.88889999.2.2"
objNewAttribute1.Put "attributeSyntax", "2.5.5.3"
objNewAttribute1.Put "isSingleValued", True
objNewAttribute1.Put "rangeUpper", 32768
objNewAttribute1.Put "showInAdvancedViewOnly", True
objNewAttribute1.Put "adminDisplayName", strAttributeName1
objNewAttribute1.Put "adminDescription", "acl id for xyratex"
objNewAttribute1.Put "oMSyntax", 64
objNewAttribute1.Put "searchFlags", 0
objNewAttribute1.Put "lDAPDisplayName", "aclid"
objNewAttribute1.Put "name", strAttributeName1
objNewAttribute1.Put "systemOnly", False
objNewAttribute1.Put "systemFlags", 16
objNewAttribute1.Put "objectCategory", "CN=Attribute-Schema," & _
                        strSchemaNamingContext
objNewAttribute1.SetInfo
WScript.Echo "Success: Created attributeSchema class object: " & _
                 objNewAttribute1.Name
				 

' Declarations for new attribute. - aclkey
Const strAttributeName2 = "aclkey" 				   ' Attribute name.
Dim objNewAttribute2                               ' New attribute.
Dim strCNAttributeName2                            ' Attribute CN.

' Create new attribute.
strCNAttributeName2 = "CN=" & strAttributeName2
Set objNewAttribute2 = objSchema.Create("attributeSchema", _
                          strCNAttributeName2)

' Set selected values for attribute.
objNewAttribute2.Put "instanceType", DS_INSTANCETYPE_NC_IS_WRITEABLE
objNewAttribute2.Put "attributeID", "1.2.840.113556.1.8000.2664.88889999.2.3"
objNewAttribute2.Put "attributeSyntax", "2.5.5.3"
objNewAttribute2.Put "isSingleValued", True
objNewAttribute2.Put "rangeUpper", 32768
objNewAttribute2.Put "showInAdvancedViewOnly", True
objNewAttribute2.Put "adminDisplayName", strAttributeName2
objNewAttribute2.Put "adminDescription", "acl key for xyratex"
objNewAttribute2.Put "oMSyntax", 64
objNewAttribute2.Put "searchFlags", 0
objNewAttribute2.Put "lDAPDisplayName", "aclkey"
objNewAttribute2.Put "name", strAttributeName2
objNewAttribute2.Put "systemOnly", False
objNewAttribute2.Put "systemFlags", 16
objNewAttribute2.Put "objectCategory", "CN=Attribute-Schema," & _
                        strSchemaNamingContext
objNewAttribute2.SetInfo
WScript.Echo "Success: Created attributeSchema class object: " & _
                 objNewAttribute2.Name				 
				 
				 
' Declarations for new attribute. - aclid 
Const strAttributeName3 = "memberUid"               ' Attribute name.
Dim objNewAttribute3                                ' New attribute.
Dim strCNAttributeName3                             ' Attribute CN.

' Create new attribute.
strCNAttributeName3 = "CN=" & strAttributeName3
Set objNewAttribute3 = objSchema.Create("attributeSchema", _
                          strCNAttributeName3)

' Set selected values for attribute.
objNewAttribute3.Put "instanceType", DS_INSTANCETYPE_NC_IS_WRITEABLE
objNewAttribute3.Put "attributeID", "1.2.840.113556.1.8000.2664.88889999.2.4"
objNewAttribute3.Put "attributeSyntax", "2.5.5.5"
objNewAttribute3.Put "isMultiValued", True
objNewAttribute3.Put "rangeUpper", 32768
objNewAttribute3.Put "showInAdvancedViewOnly", True
objNewAttribute3.Put "adminDisplayName", strAttributeName3
objNewAttribute3.Put "adminDescription", "This multivalued attribute holds the login names  of the members of a group"
objNewAttribute3.Put "oMSyntax", 64
objNewAttribute3.Put "searchFlags", 0
objNewAttribute3.Put "lDAPDisplayName", "memberUid"
objNewAttribute3.Put "name", strAttributeName3
objNewAttribute3.Put "systemOnly", False
objNewAttribute3.Put "systemFlags", 16
objNewAttribute3.Put "objectCategory", "CN=Attribute-Schema," & _
                        strSchemaNamingContext
objNewAttribute3.SetInfo
WScript.Echo "Success: Created attributeSchema class object: " & _
                 objNewAttribute3.Name			 
				 
' Update schema cache.
WScript.Echo "         Updating the schema cache."
objRoot.Put "schemaUpdateNow", 1
objRoot.SetInfo
WScript.Echo

' Declarations for new class.-XyGroupServer
Const strClassName = "XyGroupServer" 	' Class name.
Dim objNewClass                 ' New class.
Dim strCNClassName              ' Class CN.

' Create new class.
strCNClassName = "CN=" & strClassName
Set objNewClass = objSchema.Create("classSchema", strCNClassName)

' Set selected values for class.
objNewClass.Put "instanceType", DS_INSTANCETYPE_NC_IS_WRITEABLE
objNewClass.Put "subClassOf", "organizationalPerson"
objNewClass.Put "governsID", "1.2.840.113556.1.8000.2664.88889999.1.1"
objNewClass.Put "rDNAttID", "cn"
objNewClass.Put "showInAdvancedViewOnly", True
objNewClass.Put "adminDisplayName", strClassName
objNewClass.Put "adminDescription", strClassName
objNewClass.Put "objectClassCategory", 1
objNewClass.Put "lDAPDisplayName", strClassName
objNewClass.Put "name", strClassName
objNewClass.Put "systemOnly", False
objNewClass.PutEx ADS_PROPERTY_APPEND, _
                "systemPossSuperiors", Array("organizationalUnit", _
                "domainDNS")
objNewClass.Put "systemMayContain", "XyGroupServerKey" "aclid" "aclkey"
objNewClass.Put "systemMustContain", "cn"
objNewClass.Put "defaultSecurityDescriptor", _
                "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)" & _
                "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)" & _
                "(A;;RPLCLORC;;;AU)"
objNewClass.Put "systemFlags", 16
objNewClass.Put "defaultHidingValue", False
objNewClass.Put "objectCategory", "CN=Class-Schema," & _
                    strSchemaNamingContext
objNewClass.Put "defaultObjectCategory", "CN=Person," & _
                    strSchemaNamingContext
objNewClass.SetInfo
WScript.Echo "Success: Created classSchema class object: " _
              & objNewClass.Name

' Update schema cache.
WScript.Echo "         Updating the schema cache."
objRoot.Put "schemaUpdateNow", 1
objRoot.SetInfo 


