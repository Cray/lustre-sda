#include "ldap_connection.h"
#include "lrpc_misc_server.h"
#include "ConfFileReader.h"
#define DBG_LEVEL 5

	ldap_connection* ldap_connection::_instance = NULL;
	LDAP * ldap_connection::getConnection()
	{
		if (ld == NULL)
		{
			FILE *dbgstream = stderr;
			int  debug_level = DBG_LEVEL;

			int rc;
			int version;	
			struct berval   cred;
			struct berval   *servcred;

			/* get a handle to an LDAP connection */
                        const char* ServerUrl=get_attr_value("SERVER_URL");
			std::cout << "ok (ServerUrl =" << ServerUrl << ")" << std::endl;
			 
			rc = ldap_initialize(&ld, ServerUrl);
			if (rc != LDAP_SUCCESS) {
				LRPC_LOG( LOG_ERR, "ldap_initialize: %s\n", ldap_err2string( rc ) );
				return NULL;
			}
			/* Set the LDAP protocol version supported by the client
			   to 3. (By default, this is set to 2. SASL authentication
			   is part of version 3 of the LDAP protocol.) */
			version = LDAP_VERSION3;
			ldap_set_option( ld, LDAP_OPT_PROTOCOL_VERSION, &version );
			
			/* authenticate */
			cred.bv_val = PASS;
			cred.bv_len = strlen(PASS);

			int keepalive_idle = 60;
                        ldap_set_option( ld, LDAP_OPT_X_KEEPALIVE_IDLE, &keepalive_idle );

			int keepalive_probe = 10;
                        ldap_set_option( ld, LDAP_OPT_X_KEEPALIVE_PROBES, &keepalive_probe );

			int keepalive_interval = 30;
                        ldap_set_option( ld, LDAP_OPT_X_KEEPALIVE_INTERVAL, &keepalive_interval );

			const char* ConnUserDn = get_attr_value("CONN_USER_DN");

			if ( ldap_sasl_bind_s( ld, ConnUserDn , LDAP_SASL_SIMPLE,  
						&cred, NULL, NULL, &servcred ) != LDAP_SUCCESS ) {
				LRPC_LOG( LOG_ERR, "ldap_sasl_bind_s failed\n");
				ldap_perror( ld, "ldap_sasl_bind_s" );
				return NULL;
			}
		}
		return ld;

	}
