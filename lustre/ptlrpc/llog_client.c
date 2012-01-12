/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/ptlrpc/llog_client.c
 *
 * remote api for llog - client side
 *
 * Author: Andreas Dilger <adilger@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_LOG

#ifndef EXPORT_SYMTAB
#define EXPORT_SYMTAB
#endif

#ifdef __KERNEL__
#include <libcfs/libcfs.h>
#else
#include <liblustre.h>
#endif

#include <obd_class.h>
#include <lustre_log.h>
#include <lustre_net.h>
#include <libcfs/list.h>

#define LLOG_CLIENT_ENTRY(ctxt, imp) do {                             \
        cfs_mutex_down(&ctxt->loc_sem);                               \
        if (ctxt->loc_imp) {                                          \
                imp = class_import_get(ctxt->loc_imp);                \
        } else {                                                      \
                CERROR("ctxt->loc_imp == NULL for context idx %d."    \
                       "Unable to complete MDS/OSS recovery,"         \
                       "but I'll try again next time.  Not fatal.\n", \
                       ctxt->loc_idx);                                \
                imp = NULL;                                           \
                cfs_mutex_up(&ctxt->loc_sem);                         \
                return (-EINVAL);                                     \
        }                                                             \
        cfs_mutex_up(&ctxt->loc_sem);                                 \
} while(0)

#define LLOG_CLIENT_EXIT(ctxt, imp) do {                              \
        cfs_mutex_down(&ctxt->loc_sem);                               \
        if (ctxt->loc_imp != imp)                                     \
                CWARN("loc_imp has changed from %p to %p\n",          \
                       ctxt->loc_imp, imp);                           \
        class_import_put(imp);                                        \
        cfs_mutex_up(&ctxt->loc_sem);                                 \
} while(0)

/* This is a callback from the llog_* functions.
 * Assumes caller has already pushed us into the kernel context. */
static int llog_client_create(struct llog_ctxt *ctxt, struct llog_handle **res,
                              struct llog_logid *logid, char *name, int flags)
{
        struct obd_import     *imp;
        struct llogd_body     *body;
        struct llog_handle    *handle;
        struct ptlrpc_request *req = NULL;
        int                    rc;
        ENTRY;

        LLOG_CLIENT_ENTRY(ctxt, imp);

        handle = llog_alloc_handle();
        if (handle == NULL)
                RETURN(-ENOMEM);
        *res = handle;

        req = ptlrpc_request_alloc(imp, &RQF_LLOG_ORIGIN_HANDLE_CREATE);
        if (req == NULL)
                GOTO(err_free, rc = -ENOMEM);

        if (name)
                req_capsule_set_size(&req->rq_pill, &RMF_NAME, RCL_CLIENT,
                                     strlen(name) + 1);

        rc = ptlrpc_request_pack(req, LUSTRE_LOG_VERSION,
                                 LLOG_ORIGIN_HANDLE_CREATE);
        if (rc) {
                ptlrpc_request_free(req);
                req = NULL;
                GOTO(err_free, rc);
        }
        ptlrpc_request_set_replen(req);

        body = req_capsule_client_get(&req->rq_pill, &RMF_LLOGD_BODY);
        if (logid)
                body->lgd_logid = *logid;
        body->lgd_ctxt_idx = ctxt->loc_idx - 1;

        if (name) {
                char *tmp;
                tmp = req_capsule_client_sized_get(&req->rq_pill, &RMF_NAME,
                                                   strlen(name) + 1);
                LASSERT(tmp);
                strcpy(tmp, name);
        }

        rc = ptlrpc_queue_wait(req);
        if (rc)
                GOTO(err_free, rc);

        body = req_capsule_server_get(&req->rq_pill, &RMF_LLOGD_BODY);
        if (body == NULL)
                GOTO(err_free, rc =-EFAULT);

        handle->lgh_id = body->lgd_logid;
        handle->lgh_ctxt = ctxt;
        EXIT;
out:
        LLOG_CLIENT_EXIT(ctxt, imp);
        ptlrpc_req_finished(req);
        return rc;
err_free:
        *res = NULL;
        llog_free_handle(handle);
        goto out;
}

static int llog_client_destroy(struct llog_handle *loghandle)
{
        struct obd_import     *imp;
        struct ptlrpc_request *req = NULL;
        struct llogd_body     *body;
        int                    rc;
        ENTRY;

        LLOG_CLIENT_ENTRY(loghandle->lgh_ctxt, imp);
        req = ptlrpc_request_alloc_pack(imp, &RQF_LLOG_ORIGIN_HANDLE_DESTROY,
                                        LUSTRE_LOG_VERSION,
                                        LLOG_ORIGIN_HANDLE_DESTROY);
        if (req == NULL)
                GOTO(err_exit, rc =-ENOMEM);

        body = req_capsule_client_get(&req->rq_pill, &RMF_LLOGD_BODY);
        body->lgd_logid = loghandle->lgh_id;
        body->lgd_llh_flags = loghandle->lgh_hdr->llh_flags;

        ptlrpc_request_set_replen(req);
        rc = ptlrpc_queue_wait(req);
        
        ptlrpc_req_finished(req);
err_exit:
        LLOG_CLIENT_EXIT(loghandle->lgh_ctxt, imp);
        RETURN(rc);
}


static int llog_client_next_block(struct llog_handle *loghandle,
                                  int *cur_idx, int next_idx,
                                  __u64 *cur_offset, void *buf, int len)
{
        struct obd_import     *imp;
        struct ptlrpc_request *req = NULL;
        struct llogd_body     *body;
        void                  *ptr;
        int                    rc;
        ENTRY;

        LLOG_CLIENT_ENTRY(loghandle->lgh_ctxt, imp);
        req = ptlrpc_request_alloc_pack(imp, &RQF_LLOG_ORIGIN_HANDLE_NEXT_BLOCK,
                                        LUSTRE_LOG_VERSION,
                                        LLOG_ORIGIN_HANDLE_NEXT_BLOCK);
        if (req == NULL)
                GOTO(err_exit, rc =-ENOMEM);
                
        body = req_capsule_client_get(&req->rq_pill, &RMF_LLOGD_BODY);
        body->lgd_logid = loghandle->lgh_id;
        body->lgd_ctxt_idx = loghandle->lgh_ctxt->loc_idx - 1;
        body->lgd_llh_flags = loghandle->lgh_hdr->llh_flags;
        body->lgd_index = next_idx;
        body->lgd_saved_index = *cur_idx;
        body->lgd_len = len;
        body->lgd_cur_offset = *cur_offset;

        req_capsule_set_size(&req->rq_pill, &RMF_EADATA, RCL_SERVER, len);
        ptlrpc_request_set_replen(req);
        rc = ptlrpc_queue_wait(req);
        if (rc)
                GOTO(out, rc);

        body = req_capsule_server_get(&req->rq_pill, &RMF_LLOGD_BODY);
        if (body == NULL)
                GOTO(out, rc =-EFAULT);

        /* The log records are swabbed as they are processed */
        ptr = req_capsule_server_get(&req->rq_pill, &RMF_EADATA);
        if (ptr == NULL)
                GOTO(out, rc =-EFAULT);

        *cur_idx = body->lgd_saved_index;
        *cur_offset = body->lgd_cur_offset;

        memcpy(buf, ptr, len);
        EXIT;
out:
        ptlrpc_req_finished(req);
err_exit:
        LLOG_CLIENT_EXIT(loghandle->lgh_ctxt, imp);
        return rc;
}

static int llog_client_prev_block(struct llog_handle *loghandle,
                                  int prev_idx, void *buf, int len)
{
        struct obd_import     *imp;
        struct ptlrpc_request *req = NULL;
        struct llogd_body     *body;
        void                  *ptr;
        int                    rc;
        ENTRY;

        LLOG_CLIENT_ENTRY(loghandle->lgh_ctxt, imp);
        req = ptlrpc_request_alloc_pack(imp, &RQF_LLOG_ORIGIN_HANDLE_PREV_BLOCK,
                                        LUSTRE_LOG_VERSION,
                                        LLOG_ORIGIN_HANDLE_PREV_BLOCK);
        if (req == NULL)
                GOTO(err_exit, rc = -ENOMEM);

        body = req_capsule_client_get(&req->rq_pill, &RMF_LLOGD_BODY);
        body->lgd_logid = loghandle->lgh_id;
        body->lgd_ctxt_idx = loghandle->lgh_ctxt->loc_idx - 1;
        body->lgd_llh_flags = loghandle->lgh_hdr->llh_flags;
        body->lgd_index = prev_idx;
        body->lgd_len = len;

        req_capsule_set_size(&req->rq_pill, &RMF_EADATA, RCL_SERVER, len);
        ptlrpc_request_set_replen(req);

        rc = ptlrpc_queue_wait(req);
        if (rc)
                GOTO(out, rc);

        body = req_capsule_server_get(&req->rq_pill, &RMF_LLOGD_BODY);
        if (body == NULL)
                GOTO(out, rc =-EFAULT);

        ptr = req_capsule_server_get(&req->rq_pill, &RMF_EADATA);
        if (ptr == NULL)
                GOTO(out, rc =-EFAULT);

        memcpy(buf, ptr, len);
        EXIT;
out:
        ptlrpc_req_finished(req);
err_exit:
        LLOG_CLIENT_EXIT(loghandle->lgh_ctxt, imp);
        return rc;
}

static int llog_client_read_header(struct llog_handle *handle)
{
        struct obd_import     *imp;
        struct ptlrpc_request *req = NULL;
        struct llogd_body     *body;
        struct llog_log_hdr   *hdr;
        struct llog_rec_hdr   *llh_hdr;
        int                    rc;
        ENTRY;

        LLOG_CLIENT_ENTRY(handle->lgh_ctxt, imp);
        req = ptlrpc_request_alloc_pack(imp,&RQF_LLOG_ORIGIN_HANDLE_READ_HEADER,
                                        LUSTRE_LOG_VERSION,
                                        LLOG_ORIGIN_HANDLE_READ_HEADER);
        if (req == NULL)
                GOTO(err_exit, rc = -ENOMEM);

        body = req_capsule_client_get(&req->rq_pill, &RMF_LLOGD_BODY);
        body->lgd_logid = handle->lgh_id;
        body->lgd_ctxt_idx = handle->lgh_ctxt->loc_idx - 1;
        body->lgd_llh_flags = handle->lgh_hdr->llh_flags;

        ptlrpc_request_set_replen(req);
        rc = ptlrpc_queue_wait(req);
        if (rc)
                GOTO(out, rc);

        hdr = req_capsule_server_get(&req->rq_pill, &RMF_LLOG_LOG_HDR);
        if (hdr == NULL)
                GOTO(out, rc =-EFAULT);

        memcpy(handle->lgh_hdr, hdr, sizeof (*hdr));
        handle->lgh_last_idx = handle->lgh_hdr->llh_tail.lrt_index;

        /* sanity checks */
        llh_hdr = &handle->lgh_hdr->llh_hdr;
        if (llh_hdr->lrh_type != LLOG_HDR_MAGIC) {
                CERROR("bad log header magic: %#x (expecting %#x)\n",
                       llh_hdr->lrh_type, LLOG_HDR_MAGIC);
                rc = -EIO;
        } else if (llh_hdr->lrh_len != LLOG_CHUNK_SIZE) {
                CERROR("incorrectly sized log header: %#x "
                       "(expecting %#x)\n",
                       llh_hdr->lrh_len, LLOG_CHUNK_SIZE);
                CERROR("you may need to re-run lconf --write_conf.\n");
                rc = -EIO;
        }
        EXIT;
out:
        ptlrpc_req_finished(req);
err_exit:
        LLOG_CLIENT_EXIT(handle->lgh_ctxt, imp);
        return rc;
}

static int llog_client_close(struct llog_handle *handle)
{
        /* this doesn't call LLOG_ORIGIN_HANDLE_CLOSE because
           the servers all close the file at the end of every
           other LLOG_ RPC. */
        return(0);
}


struct llog_operations llog_client_ops = {
        lop_next_block:  llog_client_next_block,
        lop_prev_block:  llog_client_prev_block,
        lop_read_header: llog_client_read_header,
        lop_create:      llog_client_create,
        lop_destroy:     llog_client_destroy,
        lop_close:       llog_client_close,
};
