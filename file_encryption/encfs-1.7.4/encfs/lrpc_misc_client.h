#ifndef __LRPC_MISC_CLIENT_H__
#define __LRPC_MISC_CLIENT_H__

/*GSSRPC includes*/
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
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/param.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
/*GSS API includes*/
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>

#include <rlog/rlog.h>
#include <rlog/Error.h>
#include <rlog/RLogChannel.h>
#include <rlog/SyslogNode.h>
#include <rlog/StdioNode.h>



#define LOG_FILE "log_rpc.log"
#define LRPC_PROG 1
#define LRPC_VERSION 1


#define ENABLE 1
#define DISABLE 0

#define LRPC_CREATE 3
#define LRPC_ACCESS 2
#define LRPC_MOUNT 1
#define PROC_NULL  0

#define MSG_BUFFSIZE 100
#define VAR_BUFFSIZE 25
#define RECV_SIZE 2048
#define SEND_SIZE 2048
#define TIMEOUT_SEC 25 
#define DEFAULT_LRPC_SERVICE 300500
#define PASSKEY_SIZE 20
#define FILE_KEY_SIZE 44
#define BLOB_SIZE 44
#define BLOB_SIGN_SIZE 48
#define SERIALIZE "wiretransfer"
#define KRB5_SUCCESS 0


/*Error Codes*/
#define LRPC_LDAP_RET_ERR 0x1000
#define LRPC_KEY_GEN_ERR  0x2000
#define LRPC_BLOB_GEN_ERR 0x3000
#define LRPC_BLOBSIGN_GEN_ERR 0x4000
#define LRPC_REPLY_SUCCESS 0x5000
#define LRPC_ACL_VERIFY_ERR 0x6000

using namespace std;
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

struct createData
{
	char *fileid;
	char *aclid;	
};


struct encKey
{
        char *enckey;
	int lrpc_ret_code;
};

typedef struct extattrKeydata extattrKeydata;
typedef struct fileID fileID;
typedef struct createData createData;
typedef struct accessData accessData;
typedef struct encKey encKey;

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

char** lrpc_mount_proc( fileID *argp, CLIENT *clnt );
char** lrpc_access_proc( accessData *argp, CLIENT *clnt );
char** lrpc_create_proc( createData *argp, CLIENT *clnt );
CLIENT * lrpc_client_create( unsigned int address, unsigned int program_num, unsigned int version, unsigned short port, int sockfd );
CLIENT * lrpc_keyclient(char *lrpc_keyserver,char *_gss_service);
void lrpc_mount_call(CLIENT *lclient , fileID *id);
char* lrpc_access_call(CLIENT *lclient,accessData *ad);
extattrKeydata* lrpc_create_call(CLIENT *lclient,createData *iddata);
void lrpc_destroy_client(CLIENT *lclient);
void lrpc_create_filekey(CLIENT *lclient, createData *iddata, char **key, char **blob, char **blobsign);
void lrpc_get_key_from_blob(CLIENT *lclient, string &accessfileID, const char *blob, const char *blobsign, char **key);

extern CLIENT *g_keyclient;

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
                printf("malloc failed\n");                                  \
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
