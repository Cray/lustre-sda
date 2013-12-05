#ifndef _MDC_SECURITY_H
#define _MDC_SECURITY_H

#ifdef __KERNEL__
int mdc_req_pack_security(struct ptlrpc_request *req);
int mdc_req_pack_cr_security(struct ptlrpc_request *req);
int mdc_req_unpack_security(struct ptlrpc_request *req);
#else
#define mdc_req_pack_security(req) 0
#define mdc_req_pack_cr_security(req) 0
#define mdc_req_unpack_security(req) 0
#endif

#define mdc_select_rq_format(exp,basefmt) (exp_connect_selustre(exp) ?\
					  &(basefmt ## _SE) : &(basefmt))

#endif
