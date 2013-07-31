#ifdef __KERNEL__

#define DEBUG_SUBSYSTEM S_MDC

#include <lustre_net.h>
#include <lustre/lustre_idl.h>
#include "mdc_internal.h"

int mdc_req_pack_security(struct ptlrpc_request *req, __u32 *sid,
			  __u8 seclabel[128])
{
	struct client_obd *cli = &req->rq_import->imp_obd->u.cli;
	cfs_sid_cache_t *cache = cli->cl_sid_cache;
	__u32 lsid, rsid;

	if (cfs_get_current_sid(&lsid))
		return -EOPNOTSUPP;

	if (cfs_lsid_to_rsid(lsid, &rsid, *cache) == 0) {
		*sid = rsid;
		seclabel[0] = 0;
		return 0;
	}

	seclabel[0] = 0;
	*sid = 0;

	if (cfs_sid_to_string(lsid, seclabel))
		return -EOPNOTSUPP;

	return 0;
}

int mdc_req_pack_cr_security(struct ptlrpc_request *req, __u32 *sid,
			     __u8 seclabel[128])
{
	struct client_obd *cli = &req->rq_import->imp_obd->u.cli;
	cfs_sid_cache_t *cache = cli->cl_sid_cache;
	__u32 lsid, rsid;

	if (cfs_get_current_crsid(&lsid))
		return -EOPNOTSUPP;

	seclabel[0] = 0;
	*sid = 0;

	if (lsid == 0)
		return 0;

	if (cfs_lsid_to_rsid(lsid, &rsid, *cache) == 0) {
		*sid = rsid;
		seclabel[0] = 0;
		return 0;
	}

	if (cfs_sid_to_string(lsid, seclabel))
		return -EOPNOTSUPP;

	return 0;
}

int mdc_req_unpack_security(struct ptlrpc_request *req)
{
	struct client_obd *cli = &req->rq_import->imp_obd->u.cli;
	struct mdt_body *body = req_capsule_server_get(&req->rq_pill, &RMF_MDT_BODY);
	__u32 lsid;

	/* No translation in reply? */
	if (body->seclabel[0] == 0)
		return 0;

	if (cfs_string_to_sid(&lsid, body->seclabel, strlen(body->seclabel)))
		return -EINVAL;

	if (cfs_sid_cache_add(lsid, body->sid, *cli->cl_sid_cache))
		return -EINVAL;

	return 0;
}
#endif
