/*GSSRPC includes*/
#ifndef LRPC_MISC_SERVER_H
#define LRPC_MISC_SERVER_H

#include <gssrpc/rpc.h>
#include <gssrpc/clnt.h>
#include <gssrpc/xdr.h>
#include <gssrpc/auth.h>
#include <gssrpc/auth_gss.h>
#include <gssrpc/svc.h>
#include <gssrpc/pmap_clnt.h> 
//OPENSSL
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/engine.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/buffer.h>
#include <openssl/err.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>

#include<stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/types.h>

#include <netdb.h>
#include <netinet/tcp.h>
/*gssapi includes*/
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <string.h>
#define LDAP_DEPRECATED 1
#include <ldap.h>

#include "rpc/config.h"
#include "rpc/Cipher.h"
#include "rpc/CipherKey.h"
#include "rpc/NullCipher.h"
#include "rpc/openssl.h"
#include <iostream>
#include <vector>
#include "rpc/KeyGenerator.h"
#include <time.h>
#include <signal.h>
#define SIGN_VERIFY_SUCCESS 0
//FIXME where do you get the server IP from!!
#define LDAP_HOST "172.17.55.38" 
//FIXME where will u pick up creds from!!??
//#define USER "administrator@CALXYRA.COM"
//#define PASS "Password123"
#define ENABLE 1
#define DISABLE 0

#define PROFILING DISABLE

#define USER "administrator@FSG.COM"
#define PASS "Poc1@fsg4321"
#define PORT_NUMBER  LDAP_PORT 

#define GETEXTATTR_PROG 1
#define GETEXTATTR_VERSION 1

#define LRPC_CREATE 3
#define LRPC_ACCESS 2
#define LRPC_MOUNT 1
#define PROC_NULL  0

#define RECV_SIZE 2048
#define SEND_SIZE 2048

#define TIMEOUT_SEC 25 
#define DEFAULT_RPC_SERVICE 300500 
#define SERVICE_NAME "lrpc_keymgmt"
#define SERIALIZE "wiretransfer"
//FIXME get this from KRB5CCNAME env variable??!!
#define KEYTAB "/etc/krb5.keytab"

#define BLOB_SIZE 256
#define KEYSIZE 256
#define FILEKEYSIZE 32
#define PASSKEY_SIZE 20
#define BLOB_SIGN_SIZE 20

#define LUSTRE_MOUNT 0 
#define LUSTRE_ACCESS 1
#define LUSTRE_CREATE 2

#define REQUEST_ACCESS 1
#define REQUEST_DATA 0

/*ERROR CODES*/
#define LRPC_LDAP_RET_ERR 0x1000
#define LRPC_KEY_GEN_ERR  0x2000
#define LRPC_BLOB_GEN_ERR 0x3000
#define LRPC_BLOBSIGN_GEN_ERR 0x4000
#define LRPC_REPLY_SUCCESS 0x5000
#define LRPC_ACL_VERIFY_ERR 0x6000
#define LRPC_KEY_ACCESS_ERR 0x7000
/*Key structure*/
struct extattrKeydata
{
	char *filekey;
	char *blob;
	char *blobsign;
	int lrpc_ret_code;
};

struct accessData
{
	char *fileid;
	char *blob;
	char *blobsign;
};

struct fileID
{
	char *fileid;
};

struct encKey
{
	char *enckey;
	int lrpc_ret_code;
};

struct createData
{
	char *fileid;
	char *aclid;	
};


struct ldapData
{
	char *aclid;
	char *tgtuser;
};


typedef struct extattrKeydata extattrKeydata;
typedef struct fileID fileID;
typedef struct createData createData;
typedef struct encKey encKey;
typedef struct accessData accessData;
typedef struct ldapData ldapData;

static bool _dummy = false;
struct svc_rpc_gss_data {
	bool_t                  established;    /* context established */
	gss_ctx_id_t            ctx;            /* context id */
	struct rpc_gss_sec      sec;            /* security triple */
	gss_buffer_desc         cname;          /* GSS client name */
	u_int                   seq;            /* sequence number */
	u_int                   win;            /* sequence window */
	u_int                   seqlast;        /* last sequence number */
	uint32_t                seqmask;        /* bitmask of seqnums */
	gss_name_t              client_name;    /* unparsed name string */
	gss_buffer_desc         checksum;       /* so we can free it */
};


bool_t
xdr_extattrKeydata (XDR *xdrs, extattrKeydata *objp);
bool_t
xdr_fileID (XDR *xdrs, fileID *objp);
bool_t
xdr_createData (XDR *xdrs, createData *objp);
bool_t
xdr_accessData (XDR *xdrs, accessData *objp);
bool_t
xdr_encKey (XDR *xdrs, encKey *objp);


int ldap_get_sslconnection(LDAP **ld);
int ldap_disconnect(LDAP **ld);

encKey *
lrpc_access_svc(accessData *ad, struct svc_req *rqstp);

extattrKeydata *
lrpc_create_svc(createData *cd, const char *tgt_usr, struct svc_req *rqstp);


char *ldap_get_extattr(int requesttype,ldapData *ldData, bool &grant = _dummy);

int ldap_store_extattr(char *filter,char *ea);
char *lrpc_client_authenticate(struct svc_req * ptr_req);
int ldap_store_groupserverkey(char *filter,char *groupServerKey);
char *ldap_access_groupserverkey(bool &found, char *filter); 
void processGroupServerKey();
int ldap_store_aclkey(char *filter,char *groupServerKey);
char *ldap_access_aclkey(bool &found, char *filter); 

void processAclKey();
CipherKey get_aclkey();
CipherKey get_groupServerKey();

#define LOG_FATAL    (1)
#define LOG_ERR      (2)
#define LOG_WARN     (3)
#define LOG_INFO     (4)
#define LOG_DBG      (5)

#if 1
#define LRPC_LOG(level, ...) do {  \
	if (level <= debug_level) { \
		time_t mytime = time(0);\
		fprintf(dbgstream,"%s:%d:", __FILE__, __LINE__); \
		fprintf(dbgstream, __VA_ARGS__); \
		fprintf(dbgstream, "\n"); \
		fflush(dbgstream); \
	} \
} while (0)

#endif


extern FILE *dbgstream ;
extern int  debug_level;


#ifdef __GNUC__
#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)
#else
#define likely(x)       (x)
#define unlikely(x)     (x)
#endif


#define LRPC_ALLOC_CHECK(ptr,type,size)                                    \
	do {                                                                       \
		(ptr) = (type *) malloc((size)*sizeof(type));                      \
		if (unlikely((ptr) == NULL)) {                                     \
			printf("memory allocation failed\n");                                  \
		} else {                                                           \
			memset(ptr, 0, (size)*sizeof(type));                                       \
		}                                                                    \
	}while(0)

#define LRPC_ALLOC(ptr,type,size) LRPC_ALLOC_CHECK(ptr,type,size)

#define LRPC_FREE(ptr)                                                    \
	({                                                                            \
	 free(ptr);                                                        \
	 (ptr) = NULL;                                                         \
	 0;                                                                    \
	 })

#endif
