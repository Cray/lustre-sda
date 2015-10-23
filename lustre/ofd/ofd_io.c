/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2014 Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/ofd/ofd_io.c
 *
 * This file provides functions to handle IO requests from clients and
 * also LFSCK routines to check parent file identifier (PFID) consistency.
 *
 * Author: Alexey Zhuravlev <alexey.zhuravlev@intel.com>
 * Author: Fan Yong <fan.yong@intel.com>
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include "ofd_internal.h"

static int ofd_preprw_read(const struct lu_env *env, struct obd_export *exp,
			   struct ofd_device *ofd, const struct lu_fid *fid,
			   struct lu_attr *la, int niocount,
			   struct niobuf_remote *rnb, int *nr_local,
			   struct niobuf_local *lnb, char *jobid)
{
	struct ofd_thread_info	*info = ofd_info(env);
	struct ofd_object	*fo;
	int			 i, j, rc, tot_bytes = 0;

	ENTRY;
	LASSERT(env != NULL);

	fo = ofd_object_find(env, ofd, fid);
	if (IS_ERR(fo))
		RETURN(PTR_ERR(fo));
	LASSERT(fo != NULL);

	ofd_read_lock(env, fo);
	if (!ofd_object_exists(fo))
		GOTO(unlock, rc = -ENOENT);

	*nr_local = 0;
	for (i = 0, j = 0; i < niocount; i++) {
		rc = dt_bufs_get(env, ofd_object_child(fo), rnb + i,
				 lnb + j, 0, ofd_object_capa(env, fo));
		if (unlikely(rc < 0))
			GOTO(buf_put, rc);
		LASSERT(rc <= PTLRPC_MAX_BRW_PAGES);
		/* correct index for local buffers to continue with */
		j += rc;
		*nr_local += rc;
		LASSERT(j <= PTLRPC_MAX_BRW_PAGES);
		tot_bytes += rnb[i].rnb_len;
	}

	LASSERT(*nr_local > 0 && *nr_local <= PTLRPC_MAX_BRW_PAGES);
	rc = dt_attr_get(env, ofd_object_child(fo), la,
			 ofd_object_capa(env, fo));
	if (unlikely(rc))
		GOTO(buf_put, rc);

	rc = dt_read_prep(env, ofd_object_child(fo), lnb, *nr_local);
	if (unlikely(rc))
		GOTO(buf_put, rc);

	info->fti_obj = fo;
	ofd_counter_incr(exp, LPROC_OFD_STATS_READ, jobid, tot_bytes);
	RETURN(0);

buf_put:
	dt_bufs_put(env, ofd_object_child(fo), lnb, *nr_local);
unlock:
	ofd_read_unlock(env, fo);
	ofd_object_put(env, fo);
	return rc;
}

/**
 * Prepare buffers for write request processing.
 *
 * This function converts remote buffers from client to local buffers
 * and prepares the latter. If there is recovery in progress and required
 * object is missing then it can be re-created before write.
 *
 * \param[in] env	execution environment
 * \param[in] exp	OBD export of client
 * \param[in] ofd	OFD device
 * \param[in] fid	FID of object
 * \param[in] la	object attributes
 * \param[in] oa	OBDO structure from client
 * \param[in] objcount	always 1
 * \param[in] obj	object data
 * \param[in] rnb	remote buffers
 * \param[in] nr_local	number of local buffers
 * \param[in] lnb	local buffers
 * \param[in] jobid	job ID name
 *
 * \retval		0 on successful prepare
 * \retval		negative value on error
 */
static int ofd_preprw_write(const struct lu_env *env, struct obd_export *exp,
			    struct ofd_device *ofd, const struct lu_fid *fid,
			    struct lu_attr *la, struct obdo *oa,
			    int objcount, struct obd_ioobj *obj,
			    struct niobuf_remote *rnb, int *nr_local,
			    struct niobuf_local *lnb, char *jobid)
{
	struct ofd_thread_info	*info = ofd_info(env);
	struct ofd_object	*fo;
	int			 i, j, k, rc = 0, tot_bytes = 0;

	ENTRY;
	LASSERT(env != NULL);
	LASSERT(objcount == 1);

	if (unlikely(exp->exp_obd->obd_recovering)) {
		/* copied from ofd_precreate_object */
		/* XXX this should be consolidated to use the same code
		 *     instead of a copy, due to the ongoing risk of bugs. */
		memset(&info->fti_attr, 0, sizeof(info->fti_attr));
		info->fti_attr.la_valid = LA_TYPE | LA_MODE;
		info->fti_attr.la_mode = S_IFREG | S_ISUID | S_ISGID | 0666;
		info->fti_attr.la_valid |= LA_ATIME | LA_MTIME | LA_CTIME;
		/* Initialize a/c/m time so any client timestamp will always
		 * be newer and update the inode. ctime = 0 is also handled
		 * specially in osd_inode_setattr().  See LU-221, LU-1042 */
		info->fti_attr.la_atime = 0;
		info->fti_attr.la_mtime = 0;
		info->fti_attr.la_ctime = 0;

		fo = ofd_object_find_or_create(env, ofd, fid, &info->fti_attr);
	} else {
		fo = ofd_object_find(env, ofd, fid);
	}

	if (IS_ERR(fo))
		GOTO(out, rc = PTR_ERR(fo));
	LASSERT(fo != NULL);

	ofd_read_lock(env, fo);
	if (!ofd_object_exists(fo)) {
		CERROR("%s: BRW to missing obj "DOSTID"\n",
		       exp->exp_obd->obd_name, POSTID(&obj->ioo_oid));
		ofd_read_unlock(env, fo);
		ofd_object_put(env, fo);
		GOTO(out, rc = -ENOENT);
	}

	/* Process incoming grant info, set OBD_BRW_GRANTED flag and grant some
	 * space back if possible */
	ofd_grant_prepare_write(env, exp, oa, rnb, obj->ioo_bufcnt);

	/* parse remote buffers to local buffers and prepare the latter */
	*nr_local = 0;
	for (i = 0, j = 0; i < obj->ioo_bufcnt; i++) {
		rc = dt_bufs_get(env, ofd_object_child(fo),
				 rnb + i, lnb + j, 1,
				 ofd_object_capa(env, fo));
		if (unlikely(rc < 0))
			GOTO(err, rc);
		LASSERT(rc <= PTLRPC_MAX_BRW_PAGES);
		/* correct index for local buffers to continue with */
		for (k = 0; k < rc; k++) {
			lnb[j+k].lnb_flags = rnb[i].rnb_flags;
			if (!(rnb[i].rnb_flags & OBD_BRW_GRANTED))
				lnb[j+k].lnb_rc = -ENOSPC;

			/* remote client can't break through quota */
			if (exp_connect_rmtclient(exp))
				lnb[j+k].lnb_flags &= ~OBD_BRW_NOQUOTA;
		}
		j += rc;
		*nr_local += rc;
		LASSERT(j <= PTLRPC_MAX_BRW_PAGES);
		tot_bytes += rnb[i].rnb_len;
	}
	LASSERT(*nr_local > 0 && *nr_local <= PTLRPC_MAX_BRW_PAGES);

	rc = dt_write_prep(env, ofd_object_child(fo), lnb, *nr_local);
	if (unlikely(rc != 0))
		GOTO(err, rc);

	info->fti_obj = fo;
	ofd_counter_incr(exp, LPROC_OFD_STATS_WRITE, jobid, tot_bytes);
	RETURN(0);
err:
	dt_bufs_put(env, ofd_object_child(fo), lnb, *nr_local);
	ofd_read_unlock(env, fo);
	/* ofd_grant_prepare_write() was called, so we must commit */
	ofd_grant_commit(env, exp, rc);
	ofd_object_put(env, fo);
out:
	/* let's still process incoming grant information packed in the oa,
	 * but without enforcing grant since we won't proceed with the write.
	 * Just like a read request actually. */
	ofd_grant_prepare_read(env, exp, oa);
	return rc;
}

/**
 * Prepare bulk IO requests for processing.
 *
 * This function does initial checks of IO and calls corresponding
 * functions for read/write processing.
 *
 * \param[in] env	execution environment
 * \param[in] cmd	IO type (read/write)
 * \param[in] exp	OBD export of client
 * \param[in] oa	OBDO structure from request
 * \param[in] objcount	always 1
 * \param[in] obj	object data
 * \param[in] rnb	remote buffers
 * \param[in] nr_local	number of local buffers
 * \param[in] lnb	local buffers
 * \param[in] oti	request data from OST
 * \param[in] capa	capability
 *
 * \retval		0 on successful prepare
 * \retval		negative value on error
 */
int ofd_preprw(const struct lu_env *env, int cmd, struct obd_export *exp,
	       struct obdo *oa, int objcount, struct obd_ioobj *obj,
	       struct niobuf_remote *rnb, int *nr_local,
	       struct niobuf_local *lnb, struct obd_trans_info *oti,
	       struct lustre_capa *capa)
{
	struct tgt_session_info	*tsi = tgt_ses_info(env);
	struct ofd_device	*ofd = ofd_exp(exp);
	struct ofd_thread_info	*info;
	char			*jobid;
	const struct lu_fid	*fid = &oa->o_oi.oi_fid;
	int			 rc = 0;

	if (*nr_local > PTLRPC_MAX_BRW_PAGES) {
		CERROR("%s: bulk has too many pages %d, which exceeds the"
		       "maximum pages per RPC of %d\n",
		       exp->exp_obd->obd_name, *nr_local, PTLRPC_MAX_BRW_PAGES);
		RETURN(-EPROTO);
	}

	if (tgt_ses_req(tsi) == NULL) { /* echo client case */
		LASSERT(oti != NULL);
		info = ofd_info_init(env, exp);
		ofd_oti2info(info, oti);
		jobid = NULL;
	} else {
		info = tsi2ofd_info(tsi);
		jobid = tsi->tsi_jobid;
	}

	LASSERT(oa != NULL);

	if (OBD_FAIL_CHECK(OBD_FAIL_OST_ENOENT)) {
		struct ofd_seq		*oseq;

		oseq = ofd_seq_load(env, ofd, ostid_seq(&oa->o_oi));
		if (IS_ERR(oseq)) {
			CERROR("%s: Can not find seq for "DOSTID
			       ": rc = %ld\n", ofd_name(ofd), POSTID(&oa->o_oi),
			       PTR_ERR(oseq));
			RETURN(-EINVAL);
		}

		if (oseq->os_destroys_in_progress == 0) {
			/* don't fail lookups for orphan recovery, it causes
			 * later LBUGs when objects still exist during
			 * precreate */
			ofd_seq_put(env, oseq);
			RETURN(-ENOENT);
		}
		ofd_seq_put(env, oseq);
	}

	LASSERT(objcount == 1);
	LASSERT(obj->ioo_bufcnt > 0);

	if (cmd == OBD_BRW_WRITE) {
		rc = ofd_auth_capa(exp, fid, ostid_seq(&oa->o_oi),
				   capa, CAPA_OPC_OSS_WRITE);
		if (rc == 0) {
			la_from_obdo(&info->fti_attr, oa, OBD_MD_FLGETATTR);
			rc = ofd_preprw_write(env, exp, ofd, fid,
					      &info->fti_attr, oa, objcount,
					      obj, rnb, nr_local, lnb, jobid);
		}
	} else if (cmd == OBD_BRW_READ) {
		rc = ofd_auth_capa(exp, fid, ostid_seq(&oa->o_oi),
				   capa, CAPA_OPC_OSS_READ);
		if (rc == 0) {
			ofd_grant_prepare_read(env, exp, oa);
			rc = ofd_preprw_read(env, exp, ofd, fid,
					     &info->fti_attr, obj->ioo_bufcnt,
					     rnb, nr_local, lnb, jobid);
			obdo_from_la(oa, &info->fti_attr, LA_ATIME);
		}
	} else {
		CERROR("%s: wrong cmd %d received!\n",
		       exp->exp_obd->obd_name, cmd);
		rc = -EPROTO;
	}
	RETURN(rc);
}

/**
 * Drop reference on local buffers for read bulk IO.
 *
 * This will free all local buffers use by this read request.
 *
 * \param[in] env	execution environment
 * \param[in] ofd	OFD device
 * \param[in] fid	object FID
 * \param[in] objcount	always 1
 * \param[in] niocount	number of local buffers
 * \param[in] lnb	local buffers
 *
 * \retval		0 on successful execution
 * \retval		negative value on error
 */
static int
ofd_commitrw_read(const struct lu_env *env, struct ofd_device *ofd,
		  const struct lu_fid *fid, int objcount, int niocount,
		  struct niobuf_local *lnb)
{
	struct ofd_thread_info	*info = ofd_info(env);
	struct ofd_object *fo = info->fti_obj;

	ENTRY;

	LASSERT(niocount > 0);

	LASSERT(fo != NULL);
	LASSERT(ofd_object_exists(fo));
	dt_bufs_put(env, ofd_object_child(fo), lnb, niocount);

	ofd_read_unlock(env, fo);
	/* put is pair to object_get in ofd_preprw_read */
	ofd_object_put(env, fo);

	RETURN(0);
}

/**
 * Set attributes of object during write bulk IO processing.
 *
 * Change object attributes and write parent FID into extended
 * attributes when needed.
 *
 * \param[in] env	execution environment
 * \param[in] ofd	OFD device
 * \param[in] ofd_obj	OFD object
 * \param[in] la	object attributes
 * \param[in] ff	parent FID
 *
 * \retval		0 on successful attributes update
 * \retval		negative value on error
 */
static int
ofd_write_attr_set(const struct lu_env *env, struct ofd_device *ofd,
		   struct ofd_object *ofd_obj, struct lu_attr *la,
		   struct filter_fid *ff)
{
	struct ofd_thread_info	*info = ofd_info(env);
	__u64			 valid = la->la_valid;
	int			 rc;
	struct thandle		*th;
	struct dt_object	*dt_obj;
	int			 ff_needed = 0;

	ENTRY;

	LASSERT(la);

	dt_obj = ofd_object_child(ofd_obj);
	LASSERT(dt_obj != NULL);

	la->la_valid &= LA_UID | LA_GID | LA_SECURITY;

	rc = ofd_attr_handle_ugid(env, ofd_obj, la, 0 /* !is_setattr */);
	if (rc != 0)
		GOTO(out, rc);

	if (ff != NULL) {
		rc = ofd_object_ff_check(env, ofd_obj);
		if (rc == -ENODATA)
			ff_needed = 1;
		else if (rc < 0)
			GOTO(out, rc);
	}

	if (!la->la_valid && !ff_needed)
		/* no attributes to set */
		GOTO(out, rc = 0);

	th = ofd_trans_create(env, ofd);
	if (IS_ERR(th))
		GOTO(out, rc = PTR_ERR(th));

	if (la->la_valid) {
		rc = dt_declare_attr_set(env, dt_obj, la, th);
		if (rc)
			GOTO(out_tx, rc);
	}

	if (la->la_valid & LA_SECURITY) {
		info->fti_buf.lb_buf = la->la_seclabel;
		info->fti_buf.lb_len = strlen(la->la_seclabel) + 1;
		rc = dt_declare_xattr_set(env, dt_obj,
					  &info->fti_buf,
					  XATTR_NAME_SECURITY_SELINUX, 0,
					  th);
		if (rc)
			GOTO(out_tx, rc);
	}

	if (ff_needed) {
		info->fti_buf.lb_buf = ff;
		info->fti_buf.lb_len = sizeof(*ff);
		rc = dt_declare_xattr_set(env, dt_obj, &info->fti_buf,
					  XATTR_NAME_FID, 0, th);
		if (rc)
			GOTO(out_tx, rc);
	}

	/* We don't need a transno for this operation which will be re-executed
	 * anyway when the OST_WRITE (with a transno assigned) is replayed */
	rc = dt_trans_start_local(env, ofd->ofd_osd , th);
	if (rc)
		GOTO(out_tx, rc);

	/* set uid/gid */
	if (la->la_valid) {
		rc = dt_attr_set(env, dt_obj, la, th,
				 ofd_object_capa(env, ofd_obj));
		if (rc)
			GOTO(out_tx, rc);
	}

	/* set filter fid EA */
	if (ff_needed) {
		rc = dt_xattr_set(env, dt_obj, &info->fti_buf, XATTR_NAME_FID,
				  0, th, BYPASS_CAPA);
		if (rc)
			GOTO(out_tx, rc);
	}

	EXIT;
out_tx:
	dt_trans_stop(env, ofd->ofd_osd, th);
out:
	la->la_valid = valid;
	return rc;
}

struct ofd_soft_sync_callback {
	struct dt_txn_commit_cb	 ossc_cb;
	struct obd_export	*ossc_exp;
};

/**
 * Callback function for "soft sync" update.
 *
 * Reset fed_soft_sync_count upon committing the "soft_sync" update.
 * See ofd_soft_sync_cb_add() below for more details on soft sync.
 *
 * \param[in] env	execution environment
 * \param[in] th	transaction handle
 * \param[in] cb	callback data
 * \param[in] err	error code
 */
static void ofd_cb_soft_sync(struct lu_env *env, struct thandle *th,
			     struct dt_txn_commit_cb *cb, int err)
{
	struct ofd_soft_sync_callback	*ossc;

	ossc = container_of(cb, struct ofd_soft_sync_callback, ossc_cb);

	CDEBUG(D_INODE, "export %p soft sync count is reset\n", ossc->ossc_exp);
	atomic_set(&ossc->ossc_exp->exp_filter_data.fed_soft_sync_count, 0);

	class_export_cb_put(ossc->ossc_exp);
	OBD_FREE_PTR(ossc);
}

/**
 * Add callback for "soft sync" processing.
 *
 * The "soft sync" mechanism does asynchronous commit when OBD_BRW_SOFT_SYNC
 * flag is set in client buffers. The intention is for this operation to
 * commit pages belonging to a client which has "too many" outstanding
 * unstable pages in its cache. See LU-2139 for details.
 *
 * This function adds callback to be called when commit is done.
 *
 * \param[in] th	transaction handle
 * \param[in] exp	OBD export of client
 *
 * \retval		0 on successful callback adding
 * \retval		negative value on error
 */
static int ofd_soft_sync_cb_add(struct thandle *th, struct obd_export *exp)
{
	struct ofd_soft_sync_callback		*ossc;
	struct dt_txn_commit_cb			*dcb;
	int					 rc;

	OBD_ALLOC_PTR(ossc);
	if (ossc == NULL)
		return -ENOMEM;

	ossc->ossc_exp = class_export_cb_get(exp);

	dcb = &ossc->ossc_cb;
	dcb->dcb_func = ofd_cb_soft_sync;
	INIT_LIST_HEAD(&dcb->dcb_linkage);
	strlcpy(dcb->dcb_name, "ofd_cb_soft_sync", sizeof(dcb->dcb_name));

	rc = dt_trans_cb_add(th, dcb);
	if (rc) {
		class_export_cb_put(exp);
		OBD_FREE_PTR(ossc);
	}

	return rc;
}

/**
 * Commit bulk IO buffers to the storage.
 *
 * This function finalizes write IO processing by writing data to the disk.
 * That write can be synchronous or asynchronous depending on buffers flags.
 *
 * \param[in] env	execution environment
 * \param[in] exp	OBD export of client
 * \param[in] ofd	OFD device
 * \param[in] fid	FID of object
 * \param[in] la	object attributes
 * \param[in] ff	parent FID of object
 * \param[in] objcount	always 1
 * \param[in] niocount	number of local buffers
 * \param[in] lnb	local buffers
 * \param[in] old_rc	result of processing at this point
 *
 * \retval		0 on successful commit
 * \retval		negative value on error
 */
static int
ofd_commitrw_write(const struct lu_env *env, struct obd_export *exp,
		   struct ofd_device *ofd, const struct lu_fid *fid,
		   struct lu_attr *la, struct filter_fid *ff, int objcount,
		   int niocount, struct niobuf_local *lnb,
		   struct obd_trans_info *oti, int old_rc)
{
	struct ofd_thread_info	*info = ofd_info(env);
	struct ofd_object	*fo = info->fti_obj;
	struct dt_object	*o;
	struct thandle		*th;
	int			 rc = 0;
	int			 retries = 0;
	int			 i;
	struct filter_export_data *fed = &exp->exp_filter_data;
	bool			 soft_sync = false;
	bool			 cb_registered = false;

	ENTRY;

	LASSERT(objcount == 1);

	LASSERT(fo != NULL);
	LASSERT(ofd_object_exists(fo));

	o = ofd_object_child(fo);
	LASSERT(o != NULL);

	if (old_rc)
		GOTO(out, rc = old_rc);

	/*
	 * The first write to each object must set some attributes.  It is
	 * important to set the uid/gid before calling
	 * dt_declare_write_commit() since quota enforcement is now handled in
	 * declare phases.
	 */
	rc = ofd_write_attr_set(env, ofd, fo, la, ff);
	if (rc)
		GOTO(out, rc);

	la->la_valid &= LA_ATIME | LA_MTIME | LA_CTIME;

retry:
	th = ofd_trans_create(env, ofd);
	if (IS_ERR(th))
		GOTO(out, rc = PTR_ERR(th));

	th->th_sync |= ofd->ofd_syncjournal;
	if (th->th_sync == 0) {
		for (i = 0; i < niocount; i++) {
			if (!(lnb[i].lnb_flags & OBD_BRW_ASYNC)) {
				th->th_sync = 1;
				break;
			}
			if (lnb[i].lnb_flags & OBD_BRW_SOFT_SYNC)
				soft_sync = true;
		}
	}

	if (OBD_FAIL_CHECK(OBD_FAIL_OST_DQACQ_NET))
		GOTO(out_stop, rc = -EINPROGRESS);

	rc = dt_declare_write_commit(env, o, lnb, niocount, th);
	if (rc)
		GOTO(out_stop, rc);

	if (la->la_valid) {
		/* update [mac]time if needed */
		rc = dt_declare_attr_set(env, o, la, th);
		if (rc)
			GOTO(out_stop, rc);
	}

	rc = ofd_trans_start(env, ofd, fo, th);
	if (rc)
		GOTO(out_stop, rc);

	rc = dt_write_commit(env, o, lnb, niocount, th);
	if (rc)
		GOTO(out_stop, rc);

	if (la->la_valid) {
		rc = dt_attr_set(env, o, la, th, ofd_object_capa(env, fo));
		if (rc)
			GOTO(out_stop, rc);
	}

	/* get attr to return */
	rc = dt_attr_get(env, o, la, ofd_object_capa(env, fo));

out_stop:
	oti->oti_wait = th->th_sync;

	/* Force commit to make the just-deleted blocks
	 * reusable. LU-456 */
	if (rc == -ENOSPC)
		th->th_sync = 1;

	/* do this before trans stop in case commit has finished */
	if (!th->th_sync && soft_sync && !cb_registered) {
		ofd_soft_sync_cb_add(th, exp);
		cb_registered = true;
	}

	ofd_trans_stop(env, ofd, th, rc);
	if (rc == -ENOSPC && retries++ < 3) {
		CDEBUG(D_INODE, "retry after force commit, retries:%d\n",
		       retries);
		goto retry;
	}

	if (!soft_sync)
		/* reset fed_soft_sync_count upon non-SOFT_SYNC RPC */
		atomic_set(&fed->fed_soft_sync_count, 0);
	else if (atomic_inc_return(&fed->fed_soft_sync_count) ==
		 ofd->ofd_soft_sync_limit)
		dt_commit_async(env, ofd->ofd_osd);

out:
	dt_bufs_put(env, o, lnb, niocount);
	ofd_read_unlock(env, fo);
	/* put is pair to object_get in ofd_preprw_write */
	ofd_object_put(env, fo);
	info->fti_obj = NULL;
	ofd_grant_commit(env, info->fti_exp, old_rc);
	RETURN(rc);
}

/**
 * Commit bulk IO to the storage.
 *
 * This is companion function to the ofd_preprw(). It finishes bulk IO
 * request processing by committing buffers to the storage (WRITE) and/or
 * freeing those buffers (read/write). See ofd_commitrw_read() and
 * ofd_commitrw_write() for details about each type of IO.
 *
 * \param[in] env	execution environment
 * \param[in] cmd	IO type (READ/WRITE)
 * \param[in] exp	OBD export of client
 * \param[in] oa	OBDO structure from client
 * \param[in] objcount	always 1
 * \param[in] obj	object data
 * \param[in] rnb	remote buffers
 * \param[in] npages	number of local buffers
 * \param[in] lnb	local buffers
 * \param[in] oti	request data from OST
 * \param[in] old_rc	result of processing at this point
 *
 * \retval		0 on successful commit
 * \retval		negative value on error
 */
int ofd_commitrw(const struct lu_env *env, int cmd, struct obd_export *exp,
		 struct obdo *oa, int objcount, struct obd_ioobj *obj,
		 struct niobuf_remote *rnb, int npages,
		 struct niobuf_local *lnb, struct obd_trans_info *oti,
		 char *seclabel, int old_rc)
{
	struct ofd_thread_info	*info = ofd_info(env);
	struct ofd_mod_data	*fmd;
	__u64			 valid;
	struct ofd_device	*ofd = ofd_exp(exp);
	struct filter_fid	*ff = NULL;
	const struct lu_fid	*fid = &oa->o_oi.oi_fid;
	int			 rc = 0;

	LASSERT(npages > 0);

	if (cmd == OBD_BRW_WRITE) {
		/* Don't update timestamps if this write is older than a
		 * setattr which modifies the timestamps. b=10150 */

		/* XXX when we start having persistent reservations this needs
		 * to be changed to ofd_fmd_get() to create the fmd if it
		 * doesn't already exist so we can store the reservation handle
		 * there. */
		valid = OBD_MD_FLUID | OBD_MD_FLGID;
		fmd = ofd_fmd_find(exp, fid);
		if (!fmd || fmd->fmd_mactime_xid < info->fti_xid)
			valid |= OBD_MD_FLATIME | OBD_MD_FLMTIME |
				 OBD_MD_FLCTIME;
		ofd_fmd_put(exp, fmd);
		la_from_obdo(&info->fti_attr, oa, valid);

		if (oa->o_valid & OBD_MD_FLFID) {
			ff = &info->fti_mds_fid;
			ofd_prepare_fidea(ff, oa);
		}

		if ((info->fti_attr.la_seclabel = seclabel)) {
			info->fti_attr.la_valid |= LA_SECURITY;
			info->fti_attr.la_sllen = strlen(seclabel) + 1;
		}

		rc = ofd_commitrw_write(env, exp, ofd, fid, &info->fti_attr,
					ff, objcount, npages, lnb, oti, old_rc);
		if (rc == 0)
			obdo_from_la(oa, &info->fti_attr,
				     OFD_VALID_FLAGS | LA_GID | LA_UID);
		else
			obdo_from_la(oa, &info->fti_attr, LA_GID | LA_UID);

		/* don't report overquota flag if we failed before reaching
		 * commit */
		if (old_rc == 0 && (rc == 0 || rc == -EDQUOT)) {
			/* return the overquota flags to client */
			if (lnb[0].lnb_flags & OBD_BRW_OVER_USRQUOTA) {
				if (oa->o_valid & OBD_MD_FLFLAGS)
					oa->o_flags |= OBD_FL_NO_USRQUOTA;
				else
					oa->o_flags = OBD_FL_NO_USRQUOTA;
			}

			if (lnb[0].lnb_flags & OBD_BRW_OVER_GRPQUOTA) {
				if (oa->o_valid & OBD_MD_FLFLAGS)
					oa->o_flags |= OBD_FL_NO_GRPQUOTA;
				else
					oa->o_flags = OBD_FL_NO_GRPQUOTA;
			}

			oa->o_valid |= OBD_MD_FLFLAGS;
			oa->o_valid |= OBD_MD_FLUSRQUOTA | OBD_MD_FLGRPQUOTA;
		}
	} else if (cmd == OBD_BRW_READ) {
		struct ldlm_namespace *ns = ofd->ofd_namespace;

		/* If oa != NULL then ofd_preprw_read updated the inode
		 * atime and we should update the lvb so that other glimpses
		 * will also get the updated value. bug 5972 */
		if (oa && ns && ns->ns_lvbo && ns->ns_lvbo->lvbo_update) {
			 struct ldlm_resource *rs = NULL;

			ost_fid_build_resid(fid, &info->fti_resid);
			rs = ldlm_resource_get(ns, NULL, &info->fti_resid,
					       LDLM_EXTENT, 0);
			if (!IS_ERR(rs)) {
				ns->ns_lvbo->lvbo_update(rs, NULL, 1);
				ldlm_resource_putref(rs);
			}
		}
		rc = ofd_commitrw_read(env, ofd, fid, objcount,
				       npages, lnb);
		if (old_rc)
			rc = old_rc;
	} else {
		LBUG();
		rc = -EPROTO;
	}

	if (oti != NULL)
		ofd_info2oti(info, oti);
	RETURN(rc);
}
