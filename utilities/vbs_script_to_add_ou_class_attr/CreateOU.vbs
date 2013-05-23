
Set objDomain = GetObject("LDAP://dc=fsg1,dc=com")
Set objOU = objDomain.Create("organizationalUnit", "ou=xyratex")
hr=objOU.SetInfo