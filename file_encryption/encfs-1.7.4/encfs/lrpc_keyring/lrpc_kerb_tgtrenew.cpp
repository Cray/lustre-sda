#include "lrpc_kerb_util.h"


/*
 * Signal handler for SIGALRM.
 */
	static void
lrpc_sighandler(int s UNUSED)
{
	alarm_signaled = 1;
}

/*
 * have the  context and a principal ?, get the realm then.
 */
	static const char *
lrpc_renewkerb_get_realm(krb5_context ctx UNUSED, krb5_principal princ)
{
	krb5_data *krb_data;
	krb_data = krb5_princ_realm(ctx, princ);
	if (krb_data == NULL || krb_data->data == NULL)
		return NULL;
	return krb_data->data;
}


/*
 * obtain principal name for the krbtgt ticket for the realm.
 */
	static krb5_error_code
lrpc_gettgt_princ(krb5_context ctx, krb5_principal user, krb5_principal *princ)
{
	const char *krb_realm;

	krb_realm = lrpc_renewkerb_get_realm(ctx, user);
	if (krb_realm == NULL)
		return KRB5_CONFIG_NODEFREALM;
	return krb5_build_principal(ctx, princ, strlen(krb_realm), krb_realm, "krbtgt",
			krb_realm, (const char *) NULL);
}


/*
 * Checks if ticket expires within check period of time.
 * Returns a Kerberos status code, KRB5KRB_AP_ERR_TKT_EXPIRED if it  can be renewed.
 */
	static krb5_error_code
lrpc_renewkerb_chk_expired(krb5_context ctx, krb5_ccache cache, int refresh_tkt)
{
	krb5_creds increds, *outcreds = NULL;
	bool increds_valid = false;
	time_t now, then;
	krb5_error_code status;

	/* Obtain the ticket. */
	memset(&increds, 0, sizeof(increds));
	status = krb5_cc_get_principal(ctx, cache, &increds.client);
	if (status != 0) {
		printf("error reading cache\n");
		goto done;
	}
	status = lrpc_gettgt_princ(ctx, increds.client, &increds.server);
	if (status != 0) {
		printf("error building ticket name\n");
		goto done;
	}
	status = krb5_get_credentials(ctx, 0, cache, &increds, &outcreds);
	if (status != 0) {
		printf("cannot get current credentials\n");
		goto done;
	}
	increds_valid = true;

	/* Check the expiration time. */
	if (status == 0) {
		printf("Checking expiration time..\n");
		now = time(NULL);
		then = outcreds->times.endtime;
		if (then < now + 60 * refresh_tkt + RENEW_EXPIRE_TO)
			status = KRB5KRB_AP_ERR_TKT_EXPIRED;
		then = outcreds->times.renew_till;

		/*
		 * renew period too long.
		 */
		if (then < now + 60 * refresh_tkt + RENEW_EXPIRE_TO) {
			printf("ticket cannot be renewed too large\n");
			status = KRB5KDC_ERR_KEY_EXP;
			goto done;
		}
	}

done:
	/* Free memory. */
	if (increds_valid)
		krb5_free_cred_contents(ctx, &increds);
	if (outcreds != NULL)
		krb5_free_creds(ctx, outcreds);
	return status;
}


/*
 * Renew the user's tickets.
 */
	static krb5_error_code
lrpc_kerb_tkt_renew(krb5_context ctx, krb5_ccache cache)
{
	krb5_error_code status;
	krb5_principal user = NULL;
	krb5_creds creds, *out;
	bool creds_valid = false;
	krb5_creds in, *old = NULL;
	bool in_valid = false;

	memset(&creds, 0, sizeof(creds));
	status = krb5_cc_get_principal(ctx, cache, &user);
	if (status != 0) {
		printf("error reading cache\n");
		goto done;
	}

	char *name;
	status = krb5_unparse_name(ctx, user, &name);
	if (status != 0)
		printf("error unparsing name\n");
	else {
		printf("renewing credentials for %s\n", name);
		free(name);
	}

	status = krb5_get_renewed_creds(ctx, &creds, user, cache, NULL);
	creds_valid = true;
	out = &creds;
	if (status != 0) {
		printf("error renewing credentials\n");
		goto done;
	}

	status = krb5_cc_initialize(ctx, cache, user);
	if (status != 0) {
		printf("error reinitializing cache\n");
		goto done;
	}
	status = krb5_cc_store_cred(ctx, cache, out);
	if (status != 0) {
		printf("error storing credentials\n");
		goto done;
	}

done:
	if (user != NULL)
		krb5_free_principal(ctx, user);

	if (creds_valid)
		krb5_free_cred_contents(ctx, &creds);
	return status;
}


	int
lrpc_kerb_tgt_renew()
{
	int option, result;
	char *cachename = NULL;
	bool background = false;
	bool ignore_errors = false;
	int refresh_tkt = 0;
	krb5_context ctx;
	int check_exp_tot = 0;
	krb5_ccache cache;
	int status = 0;
	krb5_error_code code;

	refresh_tkt = 1;

	/* Establish a Krb context and set the ticket cache. */
	code = krb5_init_context(&ctx);

	if (code != 0)
		printf("error initializing Kerberos\n");
	if (cachename == NULL)
		code = krb5_cc_default(ctx, &cache);
	else
		code = krb5_cc_resolve(ctx, cachename, &cache);
	if (code != 0)
		printf("error initializing ticket cache\n");

	if (cachename != NULL)
		if (setenv("KRB5CCNAME", cachename, 1) != 0)
			printf("cannot set KRB5CCNAME environment variable\n");

	/*
	 * check for ticket initial time out time
	 */
	if (check_exp_tot != 0) {
		printf("Debug::Verifying ticket \n");
		code = lrpc_renewkerb_chk_expired(ctx, cache, check_exp_tot);
		if (code != 0 && code != KRB5KRB_AP_ERR_TKT_EXPIRED && !ignore_errors)
			return 0;
	}
	if (check_exp_tot == 0 || code == KRB5KRB_AP_ERR_TKT_EXPIRED){
		printf("Debug::Renewing tickets\n");
		if (lrpc_kerb_tkt_renew(ctx, cache) != 0 && !ignore_errors)
			return KRB5KRB_AP_ERR_TKT_EXPIRED;
	}
	if (background)
		lrpc_run_bg(0, 0);

	if (refresh_tkt > 0) {
		struct timeval timeout;
		struct sigaction sa;

		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = lrpc_sighandler;
		if (sigaction(SIGALRM, &sa, NULL) < 0)
			printf("cannot set SIGALRM handler\n");
		while (1) {
			timeout.tv_sec = refresh_tkt * 60;
			timeout.tv_usec = 0;
			select(0, NULL, NULL, NULL, &timeout);
			code = lrpc_renewkerb_chk_expired(ctx, cache, refresh_tkt);
			if (alarm_signaled || code == KRB5KRB_AP_ERR_TKT_EXPIRED) {
				if (lrpc_kerb_tkt_renew(ctx, cache) != 0 && !ignore_errors)
					return 0;
			} else if (code != 0) {
				if (!ignore_errors)
					return 1;
			}
			alarm_signaled = 0;
		}
	}


	/*done. */
	code = krb5_cc_destroy(ctx, cache);
	if (code != 0)
		printf("cannot destroy ticket cache\n");

	return 1;
}
