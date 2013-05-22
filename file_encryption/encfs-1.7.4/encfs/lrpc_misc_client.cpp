#include "lrpc_misc_client.h"
/*initial mount serialize EA*/
	bool_t
xdr_extattrKeydata (XDR *xdrs, extattrKeydata *objp)
{
	register int32_t *buf;

	if (!gssrpc_xdr_string (xdrs, &objp->filekey, 2048))
		return FALSE;
	if (!gssrpc_xdr_string (xdrs, &objp->blob, 2048))
		return FALSE;
	if (!gssrpc_xdr_string (xdrs, &objp->blobsign, 2048))
		return FALSE;
	if (!gssrpc_xdr_int (xdrs, &objp->lrpc_ret_code))
                return FALSE;
	return TRUE;
}

	bool_t
xdr_fileID (XDR *xdrs, fileID *objp)
{
	register int32_t *buf;

	if (!gssrpc_xdr_string (xdrs, &objp->fileid, 2048))
		return FALSE;
	return TRUE;
}

	bool_t
xdr_createData (XDR *xdrs, createData *objp)
{
	register int32_t *buf;

	if (!gssrpc_xdr_string (xdrs, &objp->fileid, 2048))
		return FALSE;
	if (!gssrpc_xdr_string (xdrs, &objp->aclid, 2048))
		return FALSE;
	return TRUE;
}


bool_t
xdr_accessData (XDR *xdrs, accessData *objp)
{
        register int32_t *buf;

	if (!gssrpc_xdr_string (xdrs, &objp->fileid, 2048))
                return FALSE;
        if (!gssrpc_xdr_string (xdrs, &objp->blob, 2048))
                return FALSE;
        if (!gssrpc_xdr_string (xdrs, &objp->blobsign, 2048))
                return FALSE;
        return TRUE;
}

 bool_t
xdr_encKey (XDR *xdrs, encKey *objp)
{
        register int32_t *buf;

        if (!gssrpc_xdr_string (xdrs, &objp->enckey, 2048))
                return FALSE;
	if (!gssrpc_xdr_int (xdrs, &objp->lrpc_ret_code))
                return FALSE;

        return TRUE;
}


