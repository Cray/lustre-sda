#ifndef _MDC_SECURITY_H
#define _MDC_SECURITY_H

#ifdef __KERNEL__
int mdc_req_pack_security(struct ptlrpc_request *req, __u32 *sid,
			  __u8 seclabel[128]);
int mdc_req_pack_cr_security(struct ptlrpc_request *req, __u32 *sid,
			     __u8 seclabel[128]);
int mdc_req_unpack_security(struct ptlrpc_request *req);
#else
#define mdc_req_pack_security(req, sid, seclabel)
#define mdc_req_pack_cr_security(req, sid, seclabel)
#define mdc_req_unpack_security(req)
#endif

#endif
