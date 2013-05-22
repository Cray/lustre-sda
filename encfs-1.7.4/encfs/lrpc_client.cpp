#include "lrpc_misc_client.h"
#include "ConfFileReader.h"
#define ENABLE_KEYRING DISABLE
/*Send the Request to server and Receive the Key data from server */
	char **
lrpc_mount_proc(fileID *argp, CLIENT *clnt)
{
	static char *clnt_res;

	struct timeval   interval = { TIMEOUT_SEC, 0 };
	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call (clnt, LRPC_MOUNT,
				(xdrproc_t) xdr_fileID, (caddr_t) argp,
				(xdrproc_t) xdr_extattrKeydata, (caddr_t) &clnt_res,
				interval) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&clnt_res);
}


/*Send the Request to server and Receive the Key data from server */
	char ** 
lrpc_access_proc(accessData *argp, CLIENT *clnt)
{
	static char *clnt_res;

	struct timeval   interval = { TIMEOUT_SEC, 0 };
	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call (clnt, LRPC_ACCESS,
				(xdrproc_t) xdr_accessData, (caddr_t) argp,
				(xdrproc_t) xdr_encKey, (caddr_t) &clnt_res,
				interval) != RPC_SUCCESS) {
		return 0;
	}
	return (&clnt_res);
}

/*Send request for new file creation*/
/*Send the Request to server and Receive the Key data from server */
	char **
lrpc_create_proc(createData *argp, CLIENT *clnt)
{
	static char *clnt_res;

	struct timeval   interval = { TIMEOUT_SEC, 10 };
	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call (clnt, LRPC_CREATE,
				(xdrproc_t) xdr_createData, (caddr_t) argp,
				(xdrproc_t) xdr_extattrKeydata, (caddr_t) &clnt_res,
				interval) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&clnt_res);
}


CLIENT * lrpc_client_create( unsigned int address, unsigned int program_num, unsigned int version, 
		unsigned short port, int sockfd )
{

	struct sockaddr_in lrpc_server_address ;
	int                sock = 0 ;
	CLIENT *           lclient ;
	struct timeval     interval ;

	memset( &lrpc_server_address, 0, (size_t)sizeof( lrpc_server_address ) ) ;
	lrpc_server_address.sin_port        = port ;
	lrpc_server_address.sin_family      = AF_INET ;
	lrpc_server_address.sin_addr.s_addr = address ;

	sock               = sockfd ;
	interval.tv_sec  = TIMEOUT_SEC ;
	interval.tv_usec = 0 ;


	if( sock > 0 )
	{
		if( port > 0 )
		{
			/* In tcp, it is necessary that the socket is connected to the service in the face if you do not use RPC_ANYSOCK */
			if( connect( sock, (struct sockaddr *)&lrpc_server_address, sizeof( lrpc_server_address ) ) < 0 )
				rError("cannot connect to RPC server\n" ) ;
		}
		else
		{
			/* In this case, we do not know the port side, so can not connect, it takes RPC_ANYSOCK */
			close( sock ) ;
			sock = RPC_ANYSOCK ;
		}
	}


	/* Create the lrpc client */
	if( ( lclient = gssrpc_clnttcp_create( &lrpc_server_address, program_num, version,  
					&sock, SEND_SIZE, RECV_SIZE ) ) == NULL )
	{
		char msg[MSG_BUFFSIZE] ;
		sprintf( msg, "Creation RPC %d|%d|0x%x:%d|%d", program_num, version, address, port, sock ) ;
		rError( "%s", clnt_spcreateerror( msg ) ) ;
		return NULL ;
	}

	return lclient ;
} /* Lustre_RPCClient */


CLIENT * lrpc_keyclient(char *lrpc_keyserver,char *_gss_service)
{

	CLIENT *         lclient ;
	struct rpcent *  etc_rpc ;               
	unsigned int     lrpc_server ;  
	struct hostent * hp ;
        long RpcServerNum = get_attr_value("DEFAULT_LRPC_SERVICE");
	
	unsigned int     rpc_service_num = RpcServerNum ;
	unsigned int     rpc_version = LRPC_VERSION ;

	struct rpc_gss_sec *rpcsec_gss_data = NULL;
	gss_OID            mechOid ;
	gss_buffer_desc    mechgssbuff ;
	OM_uint32          maj_stat, min_stat ;
	char               mechname[VAR_BUFFSIZE];
	char  		   gss_service[VAR_BUFFSIZE];
	
	if( isalpha(*lrpc_keyserver) )
	{
		/* get the server name */
		if( ( hp = gethostbyname(lrpc_keyserver) ) == NULL )
		{
			printf("error gethostbyname errono=%u|%s\n", errno, strerror( errno ) ) ;
			exit( 1 ) ; 
		}

		memcpy( &lrpc_server, hp->h_addr, hp->h_length ) ;
	}
	else
	{
		lrpc_server = inet_addr(lrpc_keyserver) ;
	}
	if( ( lclient = lrpc_client_create( lrpc_server, rpc_service_num, rpc_version, 0 , RPC_ANYSOCK ) ) == NULL )
	{
		printf("Creation RPC: %s\n",clnt_spcreateerror( "Creation RPC" )) ;
		exit( 1 ) ;
	}
	
	/* Set up mechOid */ 
	strcpy( mechname, "{ 1 2 840 113554 1 2 2 }"  ) ;
	mechgssbuff.value =  mechname;
	mechgssbuff.length = strlen((char*) mechgssbuff.value ) ;

	if( ( maj_stat = gss_str_to_oid( &min_stat, &mechgssbuff, &mechOid ) ) != GSS_S_COMPLETE )
	{
		rDebug("str_to_oid %u|%u\n", maj_stat, min_stat);
		exit( 1 ) ;
	}
	
	LRPC_FREE(lrpc_keyserver);
	
	rpcsec_gss_data = (struct rpc_gss_sec *)malloc (sizeof(struct rpc_gss_sec));
	/* Authentification  RPCSEC_GSS */
	rpcsec_gss_data->mech = mechOid ;
	rpcsec_gss_data->qop =  GSS_C_QOP_DEFAULT ;
	rpcsec_gss_data->svc = RPCSEC_GSS_SVC_NONE ;
	rpcsec_gss_data->svc = RPCSEC_GSS_SVC_PRIVACY ;

	memcpy(gss_service,_gss_service,strlen(_gss_service));
re_auth:
	if( (lclient->cl_auth = gssrpc_authgss_create_default( lclient, gss_service, rpcsec_gss_data ) ) == NULL )
	{
		int ret = 0;
#if ENABLE_KEYRING
		ret = lrpc_kerb_renew_tickets();
		if (ret == KRB5_SUCCESS)
			goto re_auth;
		rError("TGT Renew failed: %d\n",ret) ;
		ret = lrpc_kerb_init();
		if(ret == KRB5_SUCCESS ) goto re_auth;
#endif
		printf("Creation AUTHGSS: %s\n",clnt_spcreateerror( "Creation AUTHGSS" )) ;
		exit( 1 ) ;
	}
	
	LRPC_FREE(rpcsec_gss_data);
	return lclient ;
}


void lrpc_mount_call(CLIENT *lclient , fileID *id)
{

	/*mount*/
	extattrKeydata *ea;   /*Structure server data*/
	rDebug("Sending MOUNT request to server.") ;
	if ((ea = (extattrKeydata *)lrpc_mount_proc(id, lclient)) == NULL){

		rError("The RPC GETEXTATTR call from Client FAILED\n ");
		clnt_perror( lclient, "Error\n" ) ;
		exit(4);
	}

	rDebug("Receiving MOUNT call data from server.");
        rDebug("Receiving data from server : File key ::%s",ea->filekey);
        rDebug("Receiving data from server : Blob ::%s ",ea->blob);
        rDebug("Receiving data from server : Signed Blob ::%s",ea->blobsign);
        rDebug("Receiving data from server : RPC Status Code :: 0x%x",ea->lrpc_ret_code);
	/*mount*/
}


char* lrpc_access_call(CLIENT *lclient,accessData *ad)
{

	encKey *ckey = NULL;
	rDebug("Sending ACCESS request to server.") ;
	/*open/access*/
	if ((ckey = (encKey *)lrpc_access_proc(ad, lclient)) == 0){

		rError("The RPC VERIFYEA call from Client FAILED\n ");
		clnt_perror( lclient, "Error\n" ) ;
		return NULL;
	}

	rDebug("Receiving ACCESS call data from server.");
	rDebug("Receiving key from server : File key ::%s",ckey->enckey) ;
	rDebug("Receiving data from server : RPC Status Code :: 0x%x",ckey->lrpc_ret_code);
	return ckey->enckey;
}


extattrKeydata* lrpc_create_call(CLIENT *lclient,createData *iddata)
{

	extattrKeydata *ea = NULL;
	rDebug("Sending CREATE request to server.") ;
	if (( ea = (extattrKeydata *)lrpc_create_proc(iddata,lclient)) == NULL){

		rError("The RPC GETEXTATTR call from Client failed");
		clnt_perror( lclient, "Error\n" ) ;
		return ea;
	}

	rDebug("Receiving CREATE call data from server.");
	rDebug("Receiving data from server : File key ::%s",ea->filekey);
	rDebug("Receiving data from server : Blob ::%s ",ea->blob);
	rDebug("Receiving data from server : Signed Blob ::%s",ea->blobsign);
	rDebug("Receiving data from server : RPC Status Code :: 0x%x",ea->lrpc_ret_code);
	return ea;
}


void lrpc_destroy_client(CLIENT *lclient)
{
	auth_destroy( lclient->cl_auth ) ;
	clnt_destroy( lclient ) ;
}


void lrpc_create_filekey(CLIENT *lclient, createData *iddata, char **key, char **blob, char **blobsign)
{
	extattrKeydata *ea  = lrpc_create_call(lclient,iddata);
	if (ea->lrpc_ret_code == LRPC_REPLY_SUCCESS)
	{
	LRPC_ALLOC(*key, char, FILE_KEY_SIZE + 1);
	memset(*key, 0, FILE_KEY_SIZE + 1);
	LRPC_ALLOC(*blob, char, BLOB_SIZE + 1);
	memset(*blob, 0, BLOB_SIZE + 1);
	LRPC_ALLOC(*blobsign, char, BLOB_SIGN_SIZE + 1);
	memset(*blobsign, 0, BLOB_SIGN_SIZE + 1);
	memcpy(*key, ea->filekey, FILE_KEY_SIZE);
	memcpy(*blob, ea->blob, BLOB_SIZE);
	memcpy(*blobsign, ea->blobsign, BLOB_SIGN_SIZE);
	LRPC_FREE(iddata);
	}
	else
	{
	rDebug("Received Error ret code from server : RPC Status Code :: 0x%x",ea->lrpc_ret_code);
	}
}


void lrpc_get_key_from_blob(CLIENT *lclient, string &accessfileID ,const char *blob, const char *blobsign, char **key)
{

	accessData *ad;
	LRPC_ALLOC(ad, accessData, 1);
	LRPC_ALLOC(ad ->blob, char, BLOB_SIZE + 1);
	memset(ad->blob,0, BLOB_SIZE + 1);
	LRPC_ALLOC(ad ->blobsign, char, BLOB_SIGN_SIZE + 1);
	memset(ad->blobsign,0, BLOB_SIGN_SIZE + 1);
	LRPC_ALLOC(ad->fileid , char , accessfileID.size()+1);
	strcpy(ad->fileid ,accessfileID.c_str());
	memcpy(ad->blobsign, blobsign,BLOB_SIGN_SIZE);
	memcpy(ad->blob, blob, BLOB_SIZE);
	char * filekey =  lrpc_access_call(lclient,ad);
	if(*filekey == NULL)
        {
        rDebug("RPC failed to access key from blob");
        return;
        }
	LRPC_FREE(ad ->blobsign);
	LRPC_FREE(ad ->blob);
	LRPC_FREE(ad);
	LRPC_ALLOC(*key, char, FILE_KEY_SIZE + 1);
	memset(*key, 0, FILE_KEY_SIZE + 1);
	memcpy(*key,filekey, FILE_KEY_SIZE);
}


CLIENT *g_keyclient = NULL;

