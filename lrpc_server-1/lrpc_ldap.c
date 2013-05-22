#include "lrpc_misc_server.h"
#include "ldap_connection.h"
#define DBG_LEVEL 5
#define CONN_USER_DN "CN=Administrator, CN=Users,DC=fsg,DC=com"
#include "ConfFileReader.h"

#if 0
int ldap_get_sslconnection(LDAP **ld)
{
	FILE *dbgstream = stderr;
        int  debug_level = DBG_LEVEL;
	
	
	int rc;
	int version;	
    	struct berval   cred;
   	struct berval   *servcred;

   	/* get a handle to an LDAP connection */ 
	rc = ldap_initialize(ld, SERVER_URL);
	if (rc != LDAP_SUCCESS) {
		LRPC_LOG( LOG_ERR, "ldap_initialize: %s\n", ldap_err2string( rc ) );
		return( 1 );
	}
	/* Set the LDAP protocol version supported by the client
	   to 3. (By default, this is set to 2. SASL authentication
	   is part of version 3 of the LDAP protocol.) */
	version = LDAP_VERSION3;
	ldap_set_option( *ld, LDAP_OPT_PROTOCOL_VERSION, &version );
	/* authenticate */
	cred.bv_val = PASS;
	cred.bv_len = strlen(PASS);
	
	if ( ldap_sasl_bind_s( *ld, CONN_USER_DN, LDAP_SASL_SIMPLE,  
				&cred, NULL, NULL, &servcred ) != LDAP_SUCCESS ) {
		ldap_perror( *ld, "ldap_sasl_bind_s" );
		return( 1 );
	}
	return 0;
}


int ldap_disconnect(LDAP **ld)
{
        ldap_unbind(*ld);
	return 0;
}
#endif

char *ldap_get_extattr(int requesttype, ldapData *ldData, bool &grant) 
{ 

	FILE *dbgstream = stderr;
        int  debug_level = DBG_LEVEL;
	


	LDAP         *ld = NULL; 
	LDAPMessage  *result, *entry; 
	BerElement   *ber = NULL; 
	char         *attr = NULL; 
	char         **vals = NULL; 
	int          i, rc = 0;
	char  *aclKey = NULL; 

	char my_filter[100];
	
	sprintf(my_filter, "(cn=%s)", ldData->aclid);

#if 0
	/* Get a handle to an LDAP connection. */ 
	if ( (ld = (LDAP *)ldap_init( LDAP_HOST, PORT_NUMBER )) == NULL ) { 
		perror( "ldap_init" ); 
		return NULL; 
	} 
	/* Bind anonymously to the LDAP server. */
	rc = ldap_simple_bind_s(ld, USER, PASS); 
	if ( rc != LDAP_SUCCESS ) { 
		LRPC_LOG( LOG_ERR, "ldap_simple_bind_s: %s and rc :: %d\n", ldap_err2string(rc),rc);
		return NULL; 
	} 
#endif
	ldap_connection *ldConn = ldap_connection::getInstance();
	ld = ldConn->getConnection();

//	ldap_get_sslconnection(&ld);

	/* Search for the entry. */
	const char* FindServerKeyDn = get_attr_value("FIND_SERVER_KEY_DN");
	if ( ( rc = ldap_search_ext_s( ld, FindServerKeyDn, LDAP_SCOPE_SUBTREE, 
					my_filter, NULL, 0, NULL, NULL, LDAP_NO_LIMIT, 
					LDAP_NO_LIMIT, &result ) ) != LDAP_SUCCESS ) { 
		LRPC_LOG( LOG_ERR, "ldap_search_ext_s: %s\n", ldap_err2string(rc)); 
		return NULL; 
	} 
	entry = ldap_first_entry( ld, result ); 

	if(requesttype == REQUEST_DATA)
	{

		LRPC_ALLOC(aclKey, char, FILEKEYSIZE);

		if ( entry != NULL ) { 
			LRPC_LOG( LOG_INFO,"Retrieving extended attributes from LDAP server.");
			/* Iterate through. */ 
			for ( attr = ldap_first_attribute( ld, entry, &ber ); 
					attr != NULL; attr = ldap_next_attribute( ld, entry, ber ) ) { 
				/* For each attribute get the values*/ 
				if ((vals = (char **)ldap_get_values( ld, entry, attr)) != NULL ) { 

					for ( i = 0; vals[i] != NULL; i++ ) 
					{	 
						//fill the keys

						if(!strcmp(attr,"aclkey"))	
						{
							strcpy(aclKey,vals[i]);
//							LRPC_LOG( LOG_ERR, "Got aclkey: %s\n", ldap_err2string(rc)); 
						}
					} 
					ldap_value_free( vals ); 
				} 
				ldap_memfree( attr ); 
			} 
			if ( ber != NULL ) { 
				ber_free( ber, 0 ); 
			} 

			ldap_msgfree( result ); 
//			ldap_unbind( ld ); 
			return aclKey; 
		}
	}

	if(requesttype == REQUEST_ACCESS)
	{
		if ( entry != NULL ) {
			LRPC_LOG( LOG_INFO,"Validating ACL ID userlist data from AD.");
			/* Iterate through. */
			for ( attr = ldap_first_attribute( ld, entry, &ber );
					attr != NULL; attr = ldap_next_attribute( ld, entry, ber ) ) {
				/* For each attribute get the values*/
				if ((vals = (char **)ldap_get_values( ld, entry, attr)) != NULL ) {

					/*ACL-ID verify check*/
					if(!strcmp(attr,"memberUid"))
					{
						LRPC_LOG( LOG_INFO,"Got MemberUid::%s,validating with AD ACL DB",ldData->tgtuser);
						/*Check ACL-ID is a memeber */
						for ( i = 0; vals[i] != NULL; i++ )
						{
							//LRPC_LOG( LOG_INFO,"Got MemberUid %s", vals[i]);

							if(!strcmp(vals[i],ldData->tgtuser))
							{
								LRPC_LOG( LOG_INFO,"Access Granted User :: %s ACL ID :: %s ",ldData->tgtuser,ldData->aclid);
								grant = true;
							}
						}
					}	
					ldap_value_free( vals );
				}
				ldap_memfree( attr );
			}
			if ( ber != NULL ) {
				ber_free( ber, 0 );
			}
			ldap_msgfree( result );
//			ldap_unbind( ld );
		}
	}
	return NULL;
}


	int
ldap_store_extattr(char *filter,char *ea)
{
	
        FILE *dbgstream = stderr;
        int  debug_level = DBG_LEVEL;
	
	LDAP *ld;
	LDAPMod *list_of_attrs[2];
	LDAPMod attribute;
	LDAPControl **srvrctrls, **clntctrls;
	int          rc;
	char my_filter[100];
	sprintf(my_filter, "cn=%s,cn=Users,dc=fsg,dc=com",filter);

	/* Distinguished name of the entry that you want to modify. */
	/* Values to add or change */
	char *exattr[] = {NULL,NULL};
	exattr[0] = ea;

	//strcpy(exattr,ea);

#if 0
	/* Get a handle to an LDAP connection. */
	if ( (ld = ldap_init( LDAP_HOST, PORT_NUMBER )) == NULL ) {
		perror( "ldap_init" );
		return( 1 );
	}
	/* Bind to the server as the Directory Manager. */
	rc = ldap_simple_bind_s( ld, USER,PASS );
	if ( rc != LDAP_SUCCESS ) {
		LRPC_LOG( LOG_ERR, "ldap_simple_bind_s: %s\n", ldap_err2string( rc ) );
		ldap_unbind_s( ld );
		return( 1 );
	}
#endif
	ldap_connection *ldConn = ldap_connection::getInstance();
	ld = ldConn->getConnection();
	//ldap_get_sslconnection(&ld);	
	/* Construct the array of LDAPMod structures representing the attributes 
	   of the new entry. */

	/* Specify each change in separate LDAPMod structures */
	attribute.mod_type = "mail";
	attribute.mod_op = LDAP_MOD_REPLACE;
	attribute.mod_values = exattr;

	/* Add the pointers to these LDAPMod structures to an array */
	list_of_attrs[0] = &attribute;
	list_of_attrs[1] = NULL;
	/* Change the entry */
	if ( ldap_modify_s( ld, my_filter , list_of_attrs ) != LDAP_SUCCESS ) {
		ldap_perror( ld, "ldap_modify_s" );
		return( 1 );
	}
}

// Create ldap_access_groupserverkey
char *ldap_access_groupserverkey(bool &found, char *filter) 
{ 

	FILE *dbgstream = stderr;
        int  debug_level = DBG_LEVEL;

	LDAP         *ld; 
	LDAPMessage  *result, *entry; 
	BerElement   *ber; 
	char         *attr ; 
	char         **vals; 
	int          i, rc;
	char  *l_groupServerKey = NULL; 

	char my_filter[50];
	sprintf(my_filter, "(cn=%s)",filter);

#if 0
	/* Get a handle to an LDAP connection. */ 
	if ( (ld = (LDAP *)ldap_init( LDAP_HOST, PORT_NUMBER )) == NULL ) { 
		perror( "ldap_init" ); 
		return NULL; 
	} 
	/* Bind anonymously to the LDAP server. */ 
	rc = ldap_simple_bind_s(ld,USER,PASS); 
	if ( rc != LDAP_SUCCESS ) { 
		LRPC_LOG( LOG_ERR,"ldap_simple_bind_s: %s", ldap_err2string(rc)); 
		return NULL; 
	} 
#endif
	ldap_connection *ldConn = ldap_connection::getInstance();
	ld = ldConn->getConnection();
	//ldap_get_sslconnection(&ld);
	/* Search for the entry. */
	const char* FindServerKeyDn = get_attr_value("FIND_SERVER_KEY_DN");
        if ( ( rc = ldap_search_ext_s( ld, FindServerKeyDn, LDAP_SCOPE_SUBTREE,
                                        my_filter, NULL, 0, NULL, NULL, LDAP_NO_LIMIT,
                                        LDAP_NO_LIMIT, &result ) ) != LDAP_SUCCESS ) {
                LRPC_LOG( LOG_ERR, "ldap_search_ext_s: %s\n", ldap_err2string(rc));
                return NULL;
        }

 
	entry = ldap_first_entry( ld, result ); 

	if ( entry != NULL ) { 
		LRPC_LOG( LOG_ERR,"Retrieving extended attributes from LDAP server.");
		/* Iterate through. */ 
		for ( attr = ldap_first_attribute( ld, entry, &ber ); 
				attr != NULL; attr = ldap_next_attribute( ld, entry, ber ) ) { 
			/* For each attribute get the values*/ 
			if ((vals = (char **)ldap_get_values( ld, entry, attr)) != NULL ) { 

				for ( i = 0; vals[i] != NULL; i++ ) 
				{	 
					//fill the keys

					if(!strcmp(attr,"xyGroupServerKey"))	
					{
						int valLen = strlen(vals[i]);
						valLen++;
						LRPC_LOG( LOG_ERR, "xyGroupServerKey Length:%d and Value is :%s",valLen, vals[i]);
						LRPC_ALLOC(l_groupServerKey, char, valLen);
						strcpy(l_groupServerKey,vals[i]);
					}
				} 
				ldap_value_free( vals ); 
			} 
			ldap_memfree( attr ); 
		} 
		if ( ber != NULL ) { 
			ber_free( ber, 0 ); 
		} 

		ldap_msgfree( result ); 
//		ldap_unbind( ld ); 
		found = true;
		return l_groupServerKey; 
	}

	LRPC_LOG( LOG_ERR,"ldap_access_groupServerKey:not found"); 
	return NULL;
}

// ldap_store_groupserverkey

int
ldap_store_groupserverkey(char *filter,char *groupServerKey)
{
	FILE *dbgstream = stderr;
        int  debug_level = DBG_LEVEL;

	LDAP *ld;
	LDAPMod        **mods;
	LDAPMod attribute;
	LDAPMod key_attribute;
	LDAPControl **srvrctrls, **clntctrls;
	int          rc;
	char *object_vals[] = { "top", "xyRootGroupServer", NULL };
	char my_filter[100];
        int NUM_MOD = 3;
        sprintf(my_filter, "cn=%s,ou=xyratex,dc=fsg,dc=com",filter);

	LRPC_LOG( LOG_INFO,"ldap_store_groupserverkey : filter %s groupServerKey : %s", my_filter, groupServerKey);
	/* Distinguished name of the entry that you want to modify. */
	/* Values to add or change */
	char *exattr[] = {NULL,NULL};
	exattr[0] = groupServerKey;
	char *cn_vals[] = {NULL,NULL};
	cn_vals[0] = filter;
	
	//strcpy(exattr,ea);

#if 0
	/* Get a handle to an LDAP connection. */
	if ( (ld = ldap_init( "172.17.55.38", PORT_NUMBER )) == NULL ) {
		perror( "ldap_init" );
		return( 1 );
	}
	/* Bind to the server as the Directory Manager. */
	rc = ldap_simple_bind_s( ld,USER,PASS );
	if ( rc != LDAP_SUCCESS ) {
		LRPC_LOG( LOG_ERR, "ldap_simple_bind_s: %s\n", ldap_err2string( rc ) );
		ldap_unbind_s( ld );
		return( 1 );
	}
#endif
	ldap_connection *ldConn = ldap_connection::getInstance();
	ld = ldConn->getConnection();
	//ldap_get_sslconnection(&ld);

	/* Construct the array of LDAPMod structures representing the attributes 
	   of the new entry. */
	mods = ( LDAPMod ** ) malloc(( NUM_MOD + 1 ) * sizeof( LDAPMod * ));
	if ( mods == NULL ) {
		LRPC_LOG( LOG_ERR, "Cannot allocate memory for mods array" );
	//	exit( 1 );
	}
	
	for (int i = 0; i < NUM_MOD; i++ ) {
		if (( mods[ i ] = ( LDAPMod * ) malloc( sizeof( LDAPMod ))) == NULL ) {
			LRPC_LOG( LOG_ERR,"Cannot allocate memory for mods element");
	//	exit( 1 );
		}
	}
	mods[ 0 ]->mod_op = 0;
	mods[ 0 ]->mod_type = "objectclass";
	mods[ 0 ]->mod_values = object_vals;
	/* Specify each change in separate LDAPMod structures */
	attribute.mod_type = "cn";
	attribute.mod_op = 0;
	attribute.mod_values = cn_vals;
	mods[ 1 ] = &attribute;
	/* Specify each change in separate LDAPMod structures */
	key_attribute.mod_type = "xyGroupServerKey";
	key_attribute.mod_op = 0;
	key_attribute.mod_values = exattr;
	mods[ 2 ] = &key_attribute;
	mods[ 3 ] = NULL;

	/* Change the entry */
	if ( ldap_add_ext_s( ld, my_filter , mods, NULL, NULL ) != LDAP_SUCCESS ) {
		ldap_perror( ld, "ldap_add_ext_s" );
		return( 1 );
	}
}


int ldap_store_aclkey(char *filter,char *encoded_aclkey)
{

	FILE *dbgstream = stderr;
        int  debug_level = DBG_LEVEL;

	LDAP *ld;
	LDAPMod        **mods;
	LDAPMod attribute;
	LDAPMod key_attribute;
	LDAPMod aclid_attribute;
	LDAPMod memberUid_attribute;
	LDAPControl **srvrctrls, **clntctrls;
	int          rc;
	char *object_vals[] = { "top", "xylrpc", NULL };
	char my_filter[100];
        int NUM_MOD = 5;
        sprintf(my_filter, "cn=%s,ou=xyratex,dc=fsg,dc=com",filter);

	LRPC_LOG( LOG_ERR,"ldap_store_aclkey : filter %s aclKey : %s\n", my_filter, encoded_aclkey);
	/* Distinguished name of the entry that you want to modify. */
	/* Values to add or change */
	char *exattr[] = {NULL,NULL};
	exattr[0] = encoded_aclkey;
	char *cn_vals[] = {NULL,NULL};
	cn_vals[0] = filter;
	char *aclid_vals[] = {NULL,NULL};
	aclid_vals[0] = filter;
	char *memberUid_vals[] = {"santosh",NULL};
	
	//strcpy(exattr,ea);

#if 0
	/* Get a handle to an LDAP connection. */
	if ( (ld = ldap_init( "172.17.55.38", PORT_NUMBER )) == NULL ) {
		perror( "ldap_init" );
		return( 1 );
	}
	/* Bind to the server as the Directory Manager. */
	rc = ldap_simple_bind_s( ld,USER,PASS );
	if ( rc != LDAP_SUCCESS ) {
		LRPC_LOG( LOG_ERR, "ldap_simple_bind_s: %s", ldap_err2string( rc ) );
		ldap_unbind_s( ld );
		return( 1 );
	}
#endif
	ldap_connection *ldConn = ldap_connection::getInstance();
	ld = ldConn->getConnection();
	//ldap_get_sslconnection(&ld);
	/* Construct the array of LDAPMod structures representing the attributes 
	   of the new entry. */
	mods = ( LDAPMod ** ) malloc(( NUM_MOD + 1 ) * sizeof( LDAPMod * ));
	if ( mods == NULL ) {
		LRPC_LOG( LOG_ERR, "Cannot allocate memory for mods array" );
	//	exit( 1 );
	}
	
	for (int i = 0; i < NUM_MOD; i++ ) {
		if (( mods[ i ] = ( LDAPMod * ) malloc( sizeof( LDAPMod ))) == NULL ) {
			LRPC_LOG( LOG_ERR,"Cannot allocate memory for mods element" );
		//	exit( 1 );
		}
	}
	mods[ 0 ]->mod_op = 0;
	mods[ 0 ]->mod_type = "objectclass";
	mods[ 0 ]->mod_values = object_vals;
	/* Specify each change in separate LDAPMod structures */
	attribute.mod_type = "cn";
	attribute.mod_op = 0;
	attribute.mod_values = cn_vals;
	mods[ 1 ] = &attribute;
	/* Specify each change in separate LDAPMod structures */
	aclid_attribute.mod_type = "aclid";
	aclid_attribute.mod_op = 0;
	aclid_attribute.mod_values = aclid_vals;
	mods[ 2 ] = &aclid_attribute;
	/* Specify each change in separate LDAPMod structures */
	key_attribute.mod_type = "aclkey";
	key_attribute.mod_op = 0;
	key_attribute.mod_values = exattr;
	mods[ 3 ] = &key_attribute;
	/* Specify each change in separate LDAPMod structures */
	memberUid_attribute.mod_type = "memberUid";
	memberUid_attribute.mod_op = 0;
	memberUid_attribute.mod_values = memberUid_vals;
	mods[ 4 ] = &memberUid_attribute;
	mods[ 5 ] = NULL;

	/* Change the entry */
	if ( ldap_add_ext_s( ld, my_filter , mods, NULL, NULL ) != LDAP_SUCCESS ) {
		ldap_perror( ld, "ldap_add_ext_s" );
		return( 1 );
	}

}
char *ldap_access_aclkey(bool &found, char *filter)
{


	FILE *dbgstream = stderr;
        int  debug_level = DBG_LEVEL;

	LDAP         *ld; 
	LDAPMessage  *result, *entry; 
	BerElement   *ber; 
	char         *attr ; 
	char         **vals; 
	int          i, rc;
	char  *encoded_aclkey = NULL; 

	char my_filter[50];
	sprintf(my_filter, "(cn=%s)",filter);

#if 0
	/* Get a handle to an LDAP connection. */ 
	if ( (ld = (LDAP *)ldap_init( LDAP_HOST, PORT_NUMBER )) == NULL ) { 
		perror( "ldap_init" ); 
		return NULL; 
	} 


	/* Bind anonymously to the LDAP server. */ 
	rc = ldap_simple_bind_s(ld,USER,PASS); 
	if ( rc != LDAP_SUCCESS ) { 
		LRPC_LOG( LOG_ERR,"ldap_simple_bind_s: %s", ldap_err2string(rc)); 
		return NULL; 
	} 

#endif
	ldap_connection *ldConn = ldap_connection::getInstance();
	ld = ldConn->getConnection();
	//ldap_get_sslconnection(&ld);


	/* Search for the entry. */
	const char* FindServerKeyDn = get_attr_value("FIND_SERVER_KEY_DN");
        if ( ( rc = ldap_search_ext_s( ld, FindServerKeyDn, LDAP_SCOPE_SUBTREE,
                                        my_filter, NULL, 0, NULL, NULL, LDAP_NO_LIMIT,
                                        LDAP_NO_LIMIT, &result ) ) != LDAP_SUCCESS ) {
                LRPC_LOG( LOG_ERR, "ldap_search_ext_s: %s\n", ldap_err2string(rc));
                return NULL;
        }
 
	entry = ldap_first_entry( ld, result ); 

	if ( entry != NULL ) { 
		LRPC_LOG( LOG_ERR,"Retrieving extended attributes from LDAP server");
		/* Iterate through. */ 
		for ( attr = ldap_first_attribute( ld, entry, &ber ); 
				attr != NULL; attr = ldap_next_attribute( ld, entry, ber ) ) { 
			/* For each attribute get the values*/ 
			if ((vals = (char **)ldap_get_values( ld, entry, attr)) != NULL ) { 

				for ( i = 0; vals[i] != NULL; i++ ) 
				{	 
					//fill the keys

					if(!strcmp(attr,"aclkey"))	
					{
						int valLen = strlen(vals[i]);
						valLen++;
//						LRPC_LOG( LOG_ERR,"aclkey Length:%d and Value is :%s",valLen, vals[i]);
						LRPC_ALLOC(encoded_aclkey, char, valLen);
						strcpy(encoded_aclkey,vals[i]);
					}
				} 
				ldap_value_free( vals ); 
			} 
			ldap_memfree( attr ); 
		} 
		if ( ber != NULL ) { 
			ber_free( ber, 0 ); 
		} 

		ldap_msgfree( result ); 
//		ldap_unbind( ld ); 
		found = true;
		return encoded_aclkey; 
	}
	
	LRPC_LOG( LOG_ERR,"ldap_access_groupServerKey: not found"); 
	return NULL;
}
