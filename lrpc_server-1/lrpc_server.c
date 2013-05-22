#include "lrpc_misc_server.h"
#include "KeyGenerator.h"

#define DBG_LEVEL 5

FileKeyGenerator *keyGen = NULL;
/* options */
char options[] = "hL:N:s:S:" ;

#if PROFILING 

void
signal_callback_handler(int signum)
{
   printf("Caught signal %d\n",signum);
   // Cleanup and close up stuff here
   // Terminate program
   exit(signum);
}

#endif


/* lrpc help */
char lustre_rpchelp[] = 
"Options: %s [-hLsS] \n"
"\t [-h] 		displays the online help \n"
"\t [-s <service RPC>] 	indicates the port or service use \n"
"\t [-S <service GSSAPI>] indicates the service for the GSSAPI \n";


/* Global declares*/
static char logfile_name[MAXPATHLEN] ;    
unsigned  int rpc_service_num = DEFAULT_RPC_SERVICE ;
#define SVCAUTH_PRIVATE(auth) \
	(*(struct svc_rpc_gss_data **)&(auth)->svc_ah_private)

void lrpc_keyserver( struct svc_req * ptr_req, SVCXPRT * ptr_svc )
{

	FILE *dbgstream = stderr;
	int  debug_level = DBG_LEVEL;
	int val = 0;
	union {
		fileID fidarg;
		createData carg;
		extattrKeydata larg;
	} lrpc_args;	

	xdrproc_t _xdr_lrpc_args, _xdr_lrpc_res;
	const char *tgt_user = NULL;
	char  *lrpc_res = NULL;
	char *(*local_create)(createData *,char *, struct svc_req *);
	char *(*local_access)(accessData *, struct svc_req *);
	
	switch( ptr_req->rq_proc )
	{
		case PROC_NULL:
			LRPC_LOG( LOG_INFO, "Requested PROC_NULL" ) ;
			if( svc_getargs( ptr_svc, (xdrproc_t)xdr_void, NULL ) == FALSE )
				svcerr_decode( ptr_svc ) ;
			if( svc_sendreply( ptr_svc, (xdrproc_t)xdr_void, NULL ) == FALSE )
				svcerr_decode( ptr_svc ) ;
			break ;

		case LRPC_CREATE:
			LRPC_LOG( LOG_INFO, "Received CREATE request" ) ;
			_xdr_lrpc_args = (xdrproc_t) xdr_createData;
			_xdr_lrpc_res = (xdrproc_t) xdr_extattrKeydata;
			/*invoke the Key service stub*/
			local_create = (char *(*)(createData *, char *tgt_usr, struct svc_req *)) lrpc_create_svc;

			if( ptr_req->rq_cred.oa_flavor == RPCSEC_GSS )
			{
				tgt_user = lrpc_client_authenticate(ptr_req);
			}
			
			memset ((char *)&lrpc_args, 0, sizeof (lrpc_args));
			if (!svc_getargs (ptr_svc, (xdrproc_t) _xdr_lrpc_args, (caddr_t) &lrpc_args)) {
				svcerr_decode (ptr_svc);
				return;
			}

			lrpc_res = (*local_create)((createData *)&lrpc_args, tgt_user, ptr_req);

			LRPC_LOG( LOG_INFO, "Sending requested data.\n");
			//TODO improvise!?
			//ACL fails NULL returned!
			if(lrpc_res == NULL)
				if( svc_sendreply( ptr_svc, (xdrproc_t)xdr_void, NULL ) == FALSE )
					svcerr_decode( ptr_svc ) ;
			
			if (lrpc_res != NULL && !gssrpc_svc_sendreply(ptr_svc, (xdrproc_t) _xdr_lrpc_res, lrpc_res)) {
				svcerr_systemerr (ptr_svc);
			}
			
			if(lrpc_res !=NULL )
                        {
				LRPC_FREE(((extattrKeydata*)lrpc_res)->filekey);
                                LRPC_FREE(((extattrKeydata*)lrpc_res)->blob);
                                LRPC_FREE(((extattrKeydata*)lrpc_res)->blobsign);
                                LRPC_FREE(lrpc_res);
                        }

			if (!svc_freeargs (ptr_svc, (xdrproc_t) _xdr_lrpc_args, (caddr_t) &lrpc_args)) {
				LRPC_LOG( LOG_ERR, "unable to free lrpc_args");
			}
			break;

		case LRPC_ACCESS:
			LRPC_LOG( LOG_INFO, "Received ACCESS request" ) ;
			_xdr_lrpc_args = (xdrproc_t) xdr_accessData;
			_xdr_lrpc_res = (xdrproc_t) xdr_encKey;
			/*invoke the Key service stub*/
			local_access = (char *(*)(accessData *, struct svc_req *)) lrpc_access_svc;

			if( ptr_req->rq_cred.oa_flavor == RPCSEC_GSS )
			{
				lrpc_client_authenticate(ptr_req);
			}
			
			memset ((char *)&lrpc_args, 0, sizeof (lrpc_args));
			if (!svc_getargs (ptr_svc, (xdrproc_t) _xdr_lrpc_args, (caddr_t) &lrpc_args)) {
				svcerr_decode (ptr_svc);
				LRPC_LOG( LOG_ERR,"Failed to get the lrpc_args");
				return;
			}

			lrpc_res = (*local_access)((accessData *)&lrpc_args, ptr_req);
			LRPC_LOG( LOG_INFO,"Sending requested data.\n");
			if (lrpc_res != NULL && !gssrpc_svc_sendreply(ptr_svc, (xdrproc_t) _xdr_lrpc_res, lrpc_res)) {
				svcerr_systemerr (ptr_svc);
			}

			if (!svc_freeargs (ptr_svc, (xdrproc_t) _xdr_lrpc_args, (caddr_t) &lrpc_args)) {
				LRPC_LOG( LOG_ERR, "unable to free lrpc_args");
			//	exit (1);
			}

			if(lrpc_res !=NULL)
			{
				LRPC_FREE(((encKey*)lrpc_res)->enckey);
				LRPC_FREE(lrpc_res);
			}
			break;
	}
} /* lrpc_server */

char *lrpc_client_authenticate(struct svc_req * ptr_req)
{

	FILE *dbgstream = stderr;
	int  debug_level = DBG_LEVEL;


	struct svc_rpc_gss_data * gd = NULL ;
	gss_buffer_desc           oidbuff ;
	gss_name_t                src_name, targ_name;
	OM_uint32                 maj_stat = 0 ;
	OM_uint32                 min_stat = 0 ;

	LRPC_LOG( LOG_INFO, "Using RPCSEC_GSS" ) ;
	/* acquire credentials */
	gd = SVCAUTH_PRIVATE(ptr_req->rq_xprt->xp_auth);

	LRPC_LOG( LOG_INFO,"RPCSEC_GSS svc=%u \tRPCSEC_GSS_SVC_NONE=%u \tRPCSEC_GSS_SVC_INTEGRITY=%u \tRPCSEC_GSS_SVC_PRIVACY=%u",
			gd->sec.svc, RPCSEC_GSS_SVC_NONE, RPCSEC_GSS_SVC_INTEGRITY, RPCSEC_GSS_SVC_PRIVACY ) ;
	LRPC_LOG( LOG_INFO,"Client = %s length=%d Qop=%d",
			(char *)gd->cname.value, (int)gd->cname.length, (int)gd->sec.qop);

	if( ( maj_stat = gss_oid_to_str( &min_stat,
					gd->sec.mech,
					&oidbuff ) ) != GSS_S_COMPLETE )
	{
		return ;
	}

	/* cleanup */
	(void)gss_release_buffer( &min_stat, &oidbuff ) ;
	return gd->cname.value;
}


main( int argc, char * argv[] )
{
	FILE *dbgstream = stderr;
	int  debug_level = DBG_LEVEL;

	#if PROFILING
	// Register signal and signal handler
        signal(SIGINT, signal_callback_handler);
	#endif

	keyGen = new FileKeyGenerator(Cipher::New("AES",192));
	struct rpcent *    etc_rpc ;               
	int                c ;                    
	static char        machine_local[256] ;
	SVCXPRT *          ptr_svc ;
	char               gss_service[1024] ;
	gss_name_t         gss_service_name ;
	gss_buffer_desc    gss_service_buf ;
	char               mech[] = "kerberos_v5" ;
	OM_uint32          maj_stat, min_stat;
	/* GSS service name */
	strcpy( gss_service,  SERVICE_NAME ) ;
	processGroupServerKey();
	processAclKey();
	while( ( c = getopt( argc, argv, options ) ) != EOF )
	{
		switch( c ) 
		{

			case 'S':
				/* gss service name */
				strcpy( gss_service, optarg ) ;
				break ;

			case 's':
				/* name of the service */
				if( isalpha( (int)*optarg ) )
				{
					/* get the rpc name */
					if( ( etc_rpc = getrpcbyname( optarg ) ) == NULL )
					{
						LRPC_LOG( LOG_ERR, "Unable to resolve rpc service %s\n", optarg ) ;
					}
					else
					{
						rpc_service_num = etc_rpc->r_number ;
					}
				}
				else
				{

					rpc_service_num = atoi( optarg ) ;
				}
				break ;

			case '?':
			case 'h':
			default:
				break ;
		}
	}

	if( argc != optind )
	{
		LRPC_LOG( LOG_ERR, "Pass the required arguments" ) ;
		exit( 1 ) ;
	}

	/* obtain the machine name */
	if( gethostname( machine_local , sizeof( machine_local ) ) != 0 )
	{
		LRPC_LOG( LOG_ERR, "error gethostname: errno=%u|%s", errno, strerror( errno ) ) ;
		exit( 1 ) ;
	}


	pmap_unset( rpc_service_num, GETEXTATTR_VERSION ) ;

	LRPC_LOG( LOG_INFO, "Starting  LRPC key management server ");
	LRPC_LOG( LOG_INFO, "The machine name is %s  ", machine_local);
	LRPC_LOG( LOG_INFO, "LRPC service %d ", rpc_service_num);

#ifdef HAVE_KRB5
	if( ( maj_stat = krb5_gss_register_acceptor_identity( KEYTAB ) ) != GSS_S_COMPLETE )
	{
		char msg[256] ;

		LRPC_LOG( LOG_INFO, "Error for name krb5_gss_register_acceptor_identity %s: %d|%d = %s",
				gss_service, maj_stat, min_stat, msg ) ;

		exit( 1 ) ;
	}
#endif
	gss_service_buf.value  = gss_service ;
	gss_service_buf.length = strlen(gss_service_buf.value) + 1; 


	if( ( maj_stat = gss_import_name( &min_stat, &gss_service_buf,
					(gss_OID)GSS_C_NT_HOSTBASED_SERVICE,
					&gss_service_name ) ) != GSS_S_COMPLETE )
	{
		char msg[256] ;

		LRPC_LOG( LOG_INFO, "Import by GSS-API name %s failed: %d|%d = %s",
				gss_service, maj_stat, min_stat, msg ) ;
		exit( 1 ) ;
	}
	else
		LRPC_LOG( LOG_INFO, "Name of the service '%s' correctly imported", gss_service ) ;

	/* set the GSSAPI principal*/
	if( !gssrpc_svcauth_gss_set_svc_name( gss_service_name ) )
	{
		LRPC_LOG( LOG_ERR, "svcauth_gss_set_svc_name failed" ) ;
		exit( 1 ) ;
	}

	/* create the SVC handle */
	if( ( ptr_svc = gssrpc_svctcp_create( RPC_ANYSOCK, SEND_SIZE , RECV_SIZE ) ) == NULL )
	{
		LRPC_LOG( LOG_ERR,"svctcp_create failed" ) ;
		exit( 1 ) ;
	}

	/* Register the service */
	LRPC_LOG( LOG_INFO, "Register service %d", rpc_service_num ) ;
	if( gssrpc_svc_register( ptr_svc, rpc_service_num, GETEXTATTR_VERSION, lrpc_keyserver, IPPROTO_TCP ) == FALSE )
	{
		LRPC_LOG( LOG_ERR, "svc_register failed" ) ;
		exit( 1 ) ;
	}
	LRPC_LOG( LOG_INFO, "\n------------------------------------------\n" ) ;

	gssrpc_svc_run() ;
	delete keyGen;
}
