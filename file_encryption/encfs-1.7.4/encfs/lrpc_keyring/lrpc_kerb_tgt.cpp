#include "lrpc_kerb_util.h"
#include "../lrpc_misc_client.h"

/*
 * Signal handler for SIGALRM. 
 */
	static void
lrpc_sig_handler(int s UNUSED)
{
	alarm_signaled = 1;
}


/*
 * Given a context and a principal, get the realm.
 */
	static const char *
lrpc_kerb_acq_real(krb5_context ctx UNUSED, krb5_principal princ)
{
	krb5_data *data;
	printf("Getting the realm!\n");
	data = krb5_princ_realm(ctx, princ);
	if (data == NULL || data->data == NULL)
		printf("cannot get local Kerberos realm\n");
	return data->data;
}


/*
 * Check whether a ticket will expire within the given number of seconds.
 * Takes the context and the lkd.  Returns a Kerberos status code.
 */
	static krb5_error_code
lrpc_chk_tgt_expiration(krb5_context ctx, struct lrpc_kerb_data *lkd)
{
	krb5_creds in, *out = NULL;
	time_t now, then, offset;
	krb5_error_code status;

	/* Obtain the ticket. */
	memset(&in, 0, sizeof(in));
	in.client = lkd->kprinc;
	in.server = lkd->ksprinc;
	status = krb5_get_credentials(ctx, 0, lkd->ccache, &in, &out);

	/*
	 * Check the expiration time ,ticket that lasts a
	 * particuliar length of time based on either kerb_renew_hb or kerb_tgt_tot.
	 */
	if (status == 0) {
		printf("Verifying Expiration time\n");
		now = time(NULL);
		then = out->times.endtime;
		if (lkd->kerb_tgt_tot > 0)
			offset = 60 * lkd->kerb_tgt_tot;
		else
			offset = 60 * lkd->kerb_renew_hb + EXPIRE_RENEW;
		if (then < now + offset)
			status = KRB5KRB_AP_ERR_TKT_EXPIRED;
	}

	/* Free memory. */
	if (out != NULL)
		krb5_free_creds(ctx, out);

	return status;
}


/*
 * lrpc_tgt_auth, authenticates the user for ticket.
 */
	static void
lrpc_tgt_auth(krb5_context ctx, struct lrpc_kerb_data *lkd)
{
	krb5_error_code status;
	krb5_keytab keytab = NULL;
	krb5_creds creds;
	char *p;

	status = krb5_unparse_name(ctx, lkd->kprinc, &p);
	if (status != 0)
		printf("error unparsing name\n");
	else {
		printf("authenticating as %s\n", p);
		free(p);
	}

	if (lkd->keytab != NULL) {
		status = krb5_kt_resolve(ctx, lkd->keytab, &keytab);
		if (status != 0)
			printf("error resolving keytab %s\n",lkd->keytab);
		status = krb5_get_init_creds_keytab(ctx, &creds, lkd->kprinc,
				keytab, 0, lkd->service,
				lkd->kopts);
	} else if (lkd->stdin_passwd == true) {
		status = krb5_get_init_creds_password(ctx, &creds, lkd->kprinc,
				NULL, krb5_prompter_posix, NULL,
				0, lkd->service,
				lkd->kopts);
	} 
               
	const char *callout = NULL; 
	char *keyring_passwd = NULL;
	/*get key from keyring*/
	keyring_passwd = (char *)get_keyfrmkeyring("user","lrpc:kerb_skey", callout, KEY_SPEC_USER_KEYRING);
	if(keyring_passwd != NULL)
	{
		
		printf("Accessing keyring\n");
		status = krb5_get_init_creds_password(ctx, &creds, lkd->kprinc,
                                keyring_passwd, NULL, NULL, 0,
                                lkd->service,
                                lkd->kopts);
        } 
	else {
		char *buffer;
		buffer = (char *)getpass("Enter the kerberose password :: ");	
		//TODO FIXME add key desc data! MAY BE USE getpwuid? username princpal??
        	add_key2keyring("user","lrpc:kerb_skey",buffer, PASSWD_SIZE);

		status = krb5_get_init_creds_password(ctx, &creds, lkd->kprinc,
				buffer, NULL, NULL, 0,
				lkd->service,
				lkd->kopts);
	}
	if (status != 0)
		printf("error getting credentials\n");
	status = krb5_cc_initialize(ctx, lkd->ccache, lkd->kprinc);
	if (status != 0)
		printf("error initializing ticket cache\n");
	status = krb5_cc_store_cred(ctx, lkd->ccache, &creds);
	if (status != 0)
		printf("error storing credentials\n");

	if (creds.client == lkd->kprinc)
		creds.client = NULL;
	krb5_free_cred_contents(ctx, &creds);
	if (keytab != NULL)
		krb5_kt_close(ctx, keytab);
}


/*
 * TODO problem with REALM FIX IT! @santosh
 * Find the principal of the first entry of a keytab.
 */
	static char *
lrpc_get_princ(krb5_context ctx, const char *path)
{
	krb5_keytab keytab;
	krb5_kt_cursor cursor;
	krb5_keytab_entry entry;
	krb5_error_code status;
	char *principal = NULL;

	status = krb5_kt_resolve(ctx, path, &keytab);
	if (status != 0)
		printf("error opening %s\n", path);
	status = krb5_kt_start_seq_get(ctx, keytab, &cursor);
	if (status != 0)
		printf("error reading %s\n", path);
	status = krb5_kt_next_entry(ctx, keytab, &entry, &cursor);
	if (status == 0) {
		status = krb5_unparse_name(ctx, entry.principal, &principal);
		if (status != 0)
			printf("error unparsing name from %s\n", path);

		krb5_free_keytab_entry_contents(ctx, &entry);
	}
	krb5_kt_end_seq_get(ctx, keytab, &cursor);
	krb5_kt_close(ctx, keytab);
	if (status == 0)
		return principal;
	else {
		printf("no principal found in keytab file %s\n", path);
		return NULL;
	}
}


	int
lrpc_krb_tgt_acq()
{
	struct lrpc_kerb_data lkd;
	int opt, result;
	krb5_error_code code;
	const char *inst = NULL;
	const char *sname = NULL;
	const char *sinst = NULL;
	const char *srealm = NULL;
	const char *mode = NULL;
	const char *cache = NULL;
	char *principal = NULL;
	int lifetime = DEFAULT_LIFETIME;
	krb5_context ctx;
	krb5_deltat life_secs;
	int status = 0;
	int background = 0;
	int search_keytab = 0;
	lkd.stdin_passwd = false;
	/* Parse command-line lkd. */
	memset(&lkd, 0, sizeof(lkd));
	lkd.kerb_renew_hb = 1;

	/* Establish a K5 context. */
	code = krb5_init_context(&ctx);
	if (code != 0)
		printf("error initializing Kerberos\n");
#if 1
	//set life time of the ticket
	code = krb5_string_to_deltat( "1m", &life_secs);
            if (code != 0 || life_secs == 0)
                printf("bad lifetime value %s\n");
            lifetime = life_secs / 60;
#endif
	/* search keytab LKD  given, figure out the principal from the keytab. */
	if (search_keytab) {
		lkd.keytab = "/etc/krb5.keytab";
		principal = lrpc_get_princ(ctx, lkd.keytab);}

	/* The default principal is the name of the local user. */
	if (principal == NULL) {
		struct passwd *pwd;
		pwd = getpwuid(getuid());
		if (pwd == NULL)
			printf("no username given/no default name\n");
		principal = pwd->pw_name;
	}

	if (cache == NULL) {
		code = krb5_cc_default(ctx, &lkd.ccache);
		if (code == 0)
			cache = krb5_cc_get_name(ctx, lkd.ccache);
	} else {
		if (setenv("KRB5CCNAME", cache, 1) != 0)
			printf("cannot set KRB5CCNAME environment variable\n");
		code = krb5_cc_resolve(ctx, cache, &lkd.ccache);
	}
	if (code != 0)
		printf("error initializing ticket cache\n");

	code = krb5_parse_name(ctx, principal, &lkd.kprinc);
	if (code != 0)
		printf("error parsing %s\n", principal);


	/* Flesh out the name of the service ticket that we're obtaining. */
	if (srealm == NULL)
		srealm = lrpc_kerb_acq_real(ctx, lkd.kprinc);

	if (sname == NULL)
		sname = "krbtgt";

	if (sinst == NULL)
		sinst = srealm;

	code = krb5_build_principal(ctx, &lkd.ksprinc, strlen(srealm),
			srealm, sname, sinst, (const char *) NULL);
	if (code != 0)
		printf("error creating service principal name\n");

	/* Figure out our ticket lifetime and initialize the lkd. */
	life_secs = lifetime * 60;

	code = krb5_get_init_creds_opt_alloc(ctx, &lkd.kopts);
	if (code != 0)
		printf("error allocating credential lkd\n");

	krb5_get_init_creds_opt_set_tkt_life(lkd.kopts, life_secs);

	//TODO pass creds here

	if (lkd.kerb_tgt_tot == 0 || lrpc_chk_tgt_expiration(ctx, &lkd))
		lrpc_tgt_auth(ctx, &lkd);

	if (background)
		//daemon(0, 0);

		if (background && lrpc_chk_tgt_expiration(ctx, &lkd))
			lrpc_tgt_auth(ctx, &lkd);

	return 1;
}
