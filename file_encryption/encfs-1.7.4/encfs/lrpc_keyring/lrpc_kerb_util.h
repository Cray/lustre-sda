#include <stdio.h>
#include <errno.h>
#include <krb5.h>
#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <syslog.h>
#include <time.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <keyutils.h>
#ifdef __cplusplus
}
#endif

#define PASSWD_SIZE 15

/* The default ticket lifetime in minutes.  Default to 10 hours. */
#define DEFAULT_LIFETIME (10 * 60)
#define EXPIRE_RENEW 120
/* Used for unused parameters to silence gcc warnings. */
#define UNUSED __attribute__((__unused__))

struct lrpc_kerb_data {
        krb5_principal kprinc;
        char *service;
        krb5_principal ksprinc;
        krb5_ccache ccache;
        krb5_get_init_creds_opt *kopts;
        const char *keytab;
        int kerb_tgt_tot;
        int kerb_renew_hb;
        bool stdin_passwd;
};

static volatile sig_atomic_t alarm_signaled = 0;
/*
 * number of seconds of TO inorder to obtain a new ticket. 
 */
#define RENEW_EXPIRE_TO (2 * 60)
int
lrpc_run_bg(int nochdir, int noclose);



int revoke_key(const char *keytype, const char *desc, const char *callout, size_t keyring);
char * get_keyfrmkeyring(const char *keytype, const char *desc, const char *callout, size_t keyring);
void add_key2keyring(const char *keytype,const char *desc,const char *payload,size_t payload_len);
