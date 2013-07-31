#ifdef __KERNEL__

#define DEBUG_SUBSYSTEM S_MDC

#include <lustre_net.h>
#include <lustre/lustre_idl.h>
#include "mdc_internal.h"

int mdc_req_pack_security(struct ptlrpc_request *req)
{
	struct client_obd *cli = &req->rq_import->imp_obd->u.cli;
	cfs_sid_cache_t *cache = cli->cl_sid_cache;
	struct mdt_selustre *sel;
	__u32 lsid, rsid;

	if (!req_capsule_has_field(&req->rq_pill, &RMF_SELUSTRE, RCL_CLIENT))
		return 0;

	sel = req_capsule_client_get(&req->rq_pill, &RMF_SELUSTRE);
	LASSERT(sel != NULL);

	if (cfs_get_current_sid(&lsid))
		return -EOPNOTSUPP;

	if (cfs_lsid_to_rsid(lsid, &rsid, *cache) == 0) {
		sel->sid = rsid;
		sel->seclabel[0] = '\0';
		return 0;
	}

	sel->seclabel[0] = '\0';
	sel->sid = 0;

	if (cfs_sid_to_string(lsid, sel->seclabel))
		return -EOPNOTSUPP;

	return 0;
}

int mdc_req_pack_cr_security(struct ptlrpc_request *req)
{
	struct client_obd *cli = &req->rq_import->imp_obd->u.cli;
	cfs_sid_cache_t *cache = cli->cl_sid_cache;
	struct mdt_selustre *sel;
	__u32 lsid, rsid;

	if (!req_capsule_has_field(&req->rq_pill, &RMF_SELUSTRE, RCL_CLIENT))
		return 0;

	sel = req_capsule_client_get(&req->rq_pill, &RMF_SELUSTRE);

	if (cfs_get_current_crsid(&lsid))
		return -EOPNOTSUPP;

	sel->cseclabel[0] = '\0';
	sel->csid = 0;

	if (lsid == 0)
		return 0;

	if (cfs_lsid_to_rsid(lsid, &rsid, *cache) == 0) {
		sel->csid = rsid;
		sel->cseclabel[0] = '\0';
		return 0;
	}

	if (cfs_sid_to_string(lsid, sel->cseclabel))
		return -EOPNOTSUPP;

	return 0;
}

int mdc_req_unpack_security(struct ptlrpc_request *req)
{
	struct client_obd *cli = &req->rq_import->imp_obd->u.cli;
	struct mdt_selustre *sel;
	__u32 lsid;

	if (!req_capsule_has_field(&req->rq_pill, &RMF_SELUSTRE, RCL_SERVER))
		return 0;

	sel = req_capsule_server_get(&req->rq_pill, &RMF_SELUSTRE);

	/* No translation in reply? */
	if (sel->seclabel[0] == 0)
		return 0;

	if (cfs_string_to_sid(&lsid, sel->seclabel, strlen(sel->seclabel)))
		return -EINVAL;

	if (cfs_sid_cache_add(lsid, sel->sid, *cli->cl_sid_cache))
		return -EINVAL;

	return 0;
}
#endif
