#include <stdio.h>
#include "lrpc_kerb_util.h"
int
lrpc_krb_tgt_acq();

int 
lrpc_kerb_tgt_renew();

int main()
{
	int status ;
	lrpc_krb_tgt_acq();
	status = lrpc_kerb_tgt_renew();
	if (status == KRB5KRB_AP_ERR_TKT_EXPIRED)
		{printf("renew/tgt period has expired\n");
	lrpc_krb_tgt_acq();
	//revoke_key("user","lrpc:kerb_skey",NULL, KEY_SPEC_USER_KEYRING);
	}
	return 0;
}
