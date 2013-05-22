#include "lrpc_kerb_util.h"
#include "../lrpc_misc_client.h"

#define PASSWD_SIZE 15

krb5_ccache ccache;
krb5_context context;
char *principal = NULL , *realm = NULL, *cachefile = NULL ;
const char *callout = NULL;

char * get_keyfrmkeyring(const char *keytype, const char *desc, const char *callout, size_t keyring)
{
        int ret = 0;
        key_serial_t keyid;
        char *kerb_passwd = NULL;
        LRPC_ALLOC(kerb_passwd, char, PASSWD_SIZE);
        keyid = request_key(keytype,desc, callout,keyring);
        ret = keyctl_read(keyid, kerb_passwd, PASSWD_SIZE);
        if ( ret == -1)
        {
                printf("Key revoked.\n");
                return NULL;
        }
        return kerb_passwd;
}

int revoke_key(const char *keytype, const char *desc, const char *callout, size_t keyring)
{
        int ret = 0;
        key_serial_t keyid;
        keyid = request_key(keytype,desc, callout,keyring);
        ret = keyctl_revoke(keyid);
        return ret;
}

void add_key2keyring(const char *keytype,const char *desc,const char *payload,size_t payload_len)
{
        key_serial_t keyid = 0;
        key_serial_t keyringid =0;
        keyid = add_key(keytype, desc, payload, payload_len, KEY_SPEC_USER_KEYRING);
        printf("keyid : %d\n",keyid);
        keyctl_setperm(keyid, KEY_USR_ALL);
}


