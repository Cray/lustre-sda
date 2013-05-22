#ifndef LDAP_CONNECTION_H
#define LDAP_CONNECTION_H
#include "lrpc_misc_server.h"
#include <ldap.h>

class ldap_connection
{
public:
	static ldap_connection*	getInstance()
	{
		if( _instance == NULL )
		{
			_instance = new ldap_connection();
		}
		return _instance;
	}

	LDAP * getConnection();

	~ldap_connection()
	{
		ldap_unbind( ld );
	}

private:
	ldap_connection()
	{ 
		ld = NULL;
	};
	LDAP *ld;
	static ldap_connection* _instance;


};
#endif
