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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/llite/llite_capa.c
 *
 * Author: Lai Siyao <lsy@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/fs.h>
#include <linux/version.h>
#include <asm/uaccess.h>
#include <linux/file.h>
#include <linux/kmod.h>

#include <lustre_lite.h>
#include "llite_internal.h"

/* for obd_capa.c_list, client capa might stay in three places:
 * 1. ll_capa_list.
 * 2. ll_idle_capas.
 * 3. stand alone: just allocated.
 */

/* capas for oss writeback and those failed to renew */
static CFS_LIST_HEAD(ll_idle_capas);
static struct ptlrpc_thread ll_capa_thread;
static cfs_list_t *ll_capa_list = &capa_list[CAPA_SITE_CLIENT];

/* llite capa renewal timer */
struct timer_list ll_capa_timer;
/* for debug: indicate whether capa on llite is enabled or not */
static cfs_atomic_t ll_capa_debug = CFS_ATOMIC_INIT(0);
static unsigned long long ll_capa_renewed = 0;
static unsigned long long ll_capa_renewal_noent = 0;
static unsigned long long ll_capa_renewal_failed = 0;
static unsigned long long ll_capa_renewal_retries = 0;

static inline void update_capa_timer(struct obd_capa *ocapa, cfs_time_t expiry)
{
        if (cfs_time_before(expiry, ll_capa_timer.expires) ||
            !timer_pending(&ll_capa_timer)) {
                mod_timer(&ll_capa_timer, expiry);
                DEBUG_CAPA(D_SEC, &ocapa->c_capa,
                           "ll_capa_timer update: %lu/%lu by", expiry, jiffies);
        }
}

static inline cfs_time_t capa_renewal_time(struct obd_capa *ocapa)
{
        return cfs_time_sub(ocapa->c_expiry,
                            cfs_time_seconds(ocapa->c_capa.lc_timeout) / 2);
}

static inline int capa_is_to_expire(struct obd_capa *ocapa)
{
        return cfs_time_beforeq(capa_renewal_time(ocapa), cfs_time_current());
}

static inline int have_expired_capa(void)
{
        struct obd_capa *ocapa = NULL;
        int expired = 0;

        /* if ll_capa_list has client capa to expire or ll_idle_capas has
         * expired capa, return 1.
         */
        cfs_spin_lock(&capa_lock);
        if (!cfs_list_empty(ll_capa_list)) {
                ocapa = cfs_list_entry(ll_capa_list->next, struct obd_capa,
                                       c_list);
                expired = capa_is_to_expire(ocapa);
                if (!expired)
                        update_capa_timer(ocapa, capa_renewal_time(ocapa));
        } else if (!cfs_list_empty(&ll_idle_capas)) {
                ocapa = cfs_list_entry(ll_idle_capas.next, struct obd_capa,
                                       c_list);
                expired = capa_is_expired(ocapa);
                if (!expired)
                        update_capa_timer(ocapa, ocapa->c_expiry);
        }
        cfs_spin_unlock(&capa_lock);

        if (expired)
                DEBUG_CAPA(D_SEC, &ocapa->c_capa, "expired");
        return expired;
}

static inline int ll_capa_check_stop(void)
{
        return (ll_capa_thread.t_flags & SVC_STOPPING) ? 1: 0;
}

static void sort_add_capa(struct obd_capa *ocapa, cfs_list_t *head)
{
        struct obd_capa *tmp;
        cfs_list_t *before = NULL;

        /* TODO: client capa is sorted by expiry, this could be optimized */
        cfs_list_for_each_entry_reverse(tmp, head, c_list) {
                if (cfs_time_aftereq(ocapa->c_expiry, tmp->c_expiry)) {
                        before = &tmp->c_list;
                        break;
                }
        }

        LASSERT(&ocapa->c_list != before);
        cfs_list_add(&ocapa->c_list, before ?: head);
}

static inline int obd_capa_open_count(struct obd_capa *oc)
{
        struct ll_inode_info *lli = ll_i2info(oc->u.cli.inode);
        return cfs_atomic_read(&lli->lli_open_count);
}

static void ll_delete_capa(struct obd_capa *ocapa)
{
        struct ll_inode_info *lli = ll_i2info(ocapa->u.cli.inode);

        if (capa_for_mds(&ocapa->c_capa)) {
                LASSERT(lli->lli_mds_capa == ocapa);
                lli->lli_mds_capa = NULL;
        } else if (capa_for_oss(&ocapa->c_capa)) {
                cfs_list_del_init(&ocapa->u.cli.lli_list);
        }

        DEBUG_CAPA(D_SEC, &ocapa->c_capa, "free client");
        cfs_list_del_init(&ocapa->c_list);
        capa_count[CAPA_SITE_CLIENT]--;
        /* release the ref when alloc */
        capa_put(ocapa);
}

/* three places where client capa is deleted:
 * 1. capa_thread_main(), main place to delete expired capa.
 * 2. ll_clear_inode_capas() in ll_clear_inode().
 * 3. ll_truncate_free_capa() delete truncate capa explicitly in ll_truncate().
 */
static int capa_thread_main(void *unused)
{
        struct obd_capa *ocapa, *tmp, *next;
        struct inode *inode = NULL;
        struct l_wait_info lwi = { 0 };
        int rc;
        ENTRY;

        cfs_daemonize("ll_capa");

        ll_capa_thread.t_flags = SVC_RUNNING;
        cfs_waitq_signal(&ll_capa_thread.t_ctl_waitq);

        while (1) {
                l_wait_event(ll_capa_thread.t_ctl_waitq,
                             (ll_capa_check_stop() || have_expired_capa()),
                             &lwi);

                if (ll_capa_check_stop())
                        break;

                next = NULL;

                cfs_spin_lock(&capa_lock);
                cfs_list_for_each_entry_safe(ocapa, tmp, ll_capa_list, c_list) {
                        LASSERT(ocapa->c_capa.lc_opc != CAPA_OPC_OSS_TRUNC);

                        if (!capa_is_to_expire(ocapa)) {
                                next = ocapa;
                                break;
                        }

                        cfs_list_del_init(&ocapa->c_list);

                        /* for MDS capability, only renew those which belong to
                         * dir, or its inode is opened, or client holds LOOKUP
                         * lock.
                         */
                        if (capa_for_mds(&ocapa->c_capa) &&
                            !S_ISDIR(ocapa->u.cli.inode->i_mode) &&
                            obd_capa_open_count(ocapa) == 0 &&
                            !ll_have_md_lock(ocapa->u.cli.inode,
                                             MDS_INODELOCK_LOOKUP,
                                             LCK_MINMODE)) {
                                DEBUG_CAPA(D_SEC, &ocapa->c_capa,
                                           "skip renewal for");
                                sort_add_capa(ocapa, &ll_idle_capas);
                                continue;
                        }

                        /* for OSS capability, only renew those whose inode is
                         * opened.
                         */
                        if (capa_for_oss(&ocapa->c_capa) &&
                            obd_capa_open_count(ocapa) == 0) {
                                /* oss capa with open count == 0 won't renew,
                                 * move to idle list */
                                sort_add_capa(ocapa, &ll_idle_capas);
                                continue;
                        }

                        /* NB iput() is in ll_update_capa() */
                        inode = igrab(ocapa->u.cli.inode);
                        if (inode == NULL) {
                                DEBUG_CAPA(D_ERROR, &ocapa->c_capa,
                                           "igrab failed for");
                                continue;
                        }

                        capa_get(ocapa);
                        ll_capa_renewed++;
                        cfs_spin_unlock(&capa_lock);
                        rc = md_renew_capa(ll_i2mdexp(inode), ocapa,
                                           ll_update_capa);
                        cfs_spin_lock(&capa_lock);
                        if (rc) {
                                DEBUG_CAPA(D_ERROR, &ocapa->c_capa,
                                           "renew failed: %d", rc);
                                ll_capa_renewal_failed++;
                        }
                }

                if (next)
                        update_capa_timer(next, capa_renewal_time(next));

                cfs_list_for_each_entry_safe(ocapa, tmp, &ll_idle_capas,
                                             c_list) {
                        if (!capa_is_expired(ocapa)) {
                                if (!next)
                                        update_capa_timer(ocapa, ocapa->c_expiry);
                                break;
                        }

                        if (cfs_atomic_read(&ocapa->c_refc) > 1) {
                                DEBUG_CAPA(D_SEC, &ocapa->c_capa,
                                           "expired(c_refc %d), don't release",
                                           cfs_atomic_read(&ocapa->c_refc));
                                /* don't try to renew any more */
                                cfs_list_del_init(&ocapa->c_list);
                                continue;
                        }

                        /* expired capa is released. */
                        DEBUG_CAPA(D_SEC, &ocapa->c_capa, "release expired");
                        ll_delete_capa(ocapa);
                }

                cfs_spin_unlock(&capa_lock);
        }

        ll_capa_thread.t_flags = SVC_STOPPED;
        cfs_waitq_signal(&ll_capa_thread.t_ctl_waitq);
        RETURN(0);
}

void ll_capa_timer_callback(unsigned long unused)
{
        cfs_waitq_signal(&ll_capa_thread.t_ctl_waitq);
}

int ll_capa_thread_start(void)
{
        int rc;
        ENTRY;

        cfs_waitq_init(&ll_capa_thread.t_ctl_waitq);

        rc = cfs_create_thread(capa_thread_main, NULL, 0);
        if (rc < 0) {
                CERROR("cannot start expired capa thread: rc %d\n", rc);
                RETURN(rc);
        }
        cfs_wait_event(ll_capa_thread.t_ctl_waitq,
                       ll_capa_thread.t_flags & SVC_RUNNING);

        RETURN(0);
}

void ll_capa_thread_stop(void)
{
        ll_capa_thread.t_flags = SVC_STOPPING;
        cfs_waitq_signal(&ll_capa_thread.t_ctl_waitq);
        cfs_wait_event(ll_capa_thread.t_ctl_waitq,
                       ll_capa_thread.t_flags & SVC_STOPPED);
}

struct obd_capa *ll_osscapa_get(struct inode *inode, __u64 opc)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct obd_capa *ocapa;
        int found = 0;

        ENTRY;

        if ((ll_i2sbi(inode)->ll_flags & LL_SBI_OSS_CAPA) == 0)
                RETURN(NULL);

        LASSERT(opc == CAPA_OPC_OSS_WRITE || opc == CAPA_OPC_OSS_RW ||
                opc == CAPA_OPC_OSS_TRUNC);

        cfs_spin_lock(&capa_lock);
        cfs_list_for_each_entry(ocapa, &lli->lli_oss_capas, u.cli.lli_list) {
                if (capa_is_expired(ocapa))
                        continue;
                if ((opc & CAPA_OPC_OSS_WRITE) &&
                    capa_opc_supported(&ocapa->c_capa, CAPA_OPC_OSS_WRITE)) {
                        found = 1;
                        break;
                } else if ((opc & CAPA_OPC_OSS_READ) &&
                           capa_opc_supported(&ocapa->c_capa,
                                              CAPA_OPC_OSS_READ)) {
                        found = 1;
                        break;
                } else if ((opc & CAPA_OPC_OSS_TRUNC) &&
                           capa_opc_supported(&ocapa->c_capa, opc)) {
                        found = 1;
                        break;
                }
        }

        if (found) {
                LASSERT(lu_fid_eq(capa_fid(&ocapa->c_capa),
                                  ll_inode2fid(inode)));
                LASSERT(ocapa->c_site == CAPA_SITE_CLIENT);

                capa_get(ocapa);

                DEBUG_CAPA(D_SEC, &ocapa->c_capa, "found client");
        } else {
                ocapa = NULL;

                if (cfs_atomic_read(&ll_capa_debug)) {
                        CERROR("no capability for "DFID" opc "LPX64"\n",
                               PFID(&lli->lli_fid), opc);
                        cfs_atomic_set(&ll_capa_debug, 0);
                }
        }
        cfs_spin_unlock(&capa_lock);

        RETURN(ocapa);
}
EXPORT_SYMBOL(ll_osscapa_get);

struct obd_capa *ll_mdscapa_get(struct inode *inode)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct obd_capa *ocapa;
        ENTRY;

        LASSERT(inode != NULL);

        if ((ll_i2sbi(inode)->ll_flags & LL_SBI_MDS_CAPA) == 0)
                RETURN(NULL);

        cfs_spin_lock(&capa_lock);
        ocapa = capa_get(lli->lli_mds_capa);
        cfs_spin_unlock(&capa_lock);
        if (!ocapa && cfs_atomic_read(&ll_capa_debug)) {
                CERROR("no mds capability for "DFID"\n", PFID(&lli->lli_fid));
                cfs_atomic_set(&ll_capa_debug, 0);
        }

        RETURN(ocapa);
}

static struct obd_capa *do_add_mds_capa(struct inode *inode,
                                        struct obd_capa *ocapa)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct obd_capa *old = lli->lli_mds_capa;
        struct lustre_capa *capa = &ocapa->c_capa;

        if (!old) {
                ocapa->u.cli.inode = inode;
                lli->lli_mds_capa = ocapa;
                capa_count[CAPA_SITE_CLIENT]++;

                DEBUG_CAPA(D_SEC, capa, "add MDS");
        } else {
                cfs_spin_lock(&old->c_lock);
                old->c_capa = *capa;
                cfs_spin_unlock(&old->c_lock);

                DEBUG_CAPA(D_SEC, capa, "update MDS");

                capa_put(ocapa);
                ocapa = old;
        }
        return ocapa;
}

static struct obd_capa *do_lookup_oss_capa(struct inode *inode, int opc)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct obd_capa *ocapa;

        /* inside capa_lock */
        cfs_list_for_each_entry(ocapa, &lli->lli_oss_capas, u.cli.lli_list) {
                if ((capa_opc(&ocapa->c_capa) & opc) != opc)
                        continue;

                LASSERT(lu_fid_eq(capa_fid(&ocapa->c_capa),
                                  ll_inode2fid(inode)));
                LASSERT(ocapa->c_site == CAPA_SITE_CLIENT);

                DEBUG_CAPA(D_SEC, &ocapa->c_capa, "found client");
                return ocapa;
        }

        return NULL;
}

static inline void inode_add_oss_capa(struct inode *inode,
                                      struct obd_capa *ocapa)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct obd_capa *tmp;
        cfs_list_t *next = NULL;

        /* capa is sorted in lli_oss_capas so lookup can always find the
         * latest one */
        cfs_list_for_each_entry(tmp, &lli->lli_oss_capas, u.cli.lli_list) {
                if (cfs_time_after(ocapa->c_expiry, tmp->c_expiry)) {
                        next = &tmp->u.cli.lli_list;
                        break;
                }
        }
        LASSERT(&ocapa->u.cli.lli_list != next);
        cfs_list_move_tail(&ocapa->u.cli.lli_list, next ?: &lli->lli_oss_capas);
}

static struct obd_capa *do_add_oss_capa(struct inode *inode,
                                        struct obd_capa *ocapa)
{
        struct obd_capa *old;
        struct lustre_capa *capa = &ocapa->c_capa;

        LASSERTF(S_ISREG(inode->i_mode),
                 "inode has oss capa, but not regular file, mode: %d\n",
                 inode->i_mode);

        /* FIXME: can't replace it so easily with fine-grained opc */
        old = do_lookup_oss_capa(inode, capa_opc(capa) & CAPA_OPC_OSS_ONLY);
        if (!old) {
                ocapa->u.cli.inode = inode;
                CFS_INIT_LIST_HEAD(&ocapa->u.cli.lli_list);
                capa_count[CAPA_SITE_CLIENT]++;

                DEBUG_CAPA(D_SEC, capa, "add OSS");
        } else {
                cfs_spin_lock(&old->c_lock);
                old->c_capa = *capa;
                cfs_spin_unlock(&old->c_lock);

                DEBUG_CAPA(D_SEC, capa, "update OSS");

                capa_put(ocapa);
                ocapa = old;
        }

        inode_add_oss_capa(inode, ocapa);
        return ocapa;
}

struct obd_capa *ll_add_capa(struct inode *inode, struct obd_capa *ocapa)
{
        cfs_spin_lock(&capa_lock);
        ocapa = capa_for_mds(&ocapa->c_capa) ? do_add_mds_capa(inode, ocapa) :
                                               do_add_oss_capa(inode, ocapa);

        /* truncate capa won't renew */
        if (ocapa->c_capa.lc_opc != CAPA_OPC_OSS_TRUNC) {
                set_capa_expiry(ocapa);
                cfs_list_del_init(&ocapa->c_list);
                sort_add_capa(ocapa, ll_capa_list);

                update_capa_timer(ocapa, capa_renewal_time(ocapa));
        }

        cfs_spin_unlock(&capa_lock);

        cfs_atomic_set(&ll_capa_debug, 1);
        return ocapa;
}

static inline void delay_capa_renew(struct obd_capa *oc, cfs_time_t delay)
{
        /* NB: set a fake expiry for this capa to prevent it renew too soon */
        oc->c_expiry = cfs_time_add(oc->c_expiry, cfs_time_seconds(delay));
}

int ll_update_capa(struct obd_capa *ocapa, struct lustre_capa *capa)
{
        struct inode *inode = ocapa->u.cli.inode;
        int rc = 0;
        ENTRY;

        LASSERT(ocapa);

        if (IS_ERR(capa)) {
                /* set error code */
                rc = PTR_ERR(capa);
                cfs_spin_lock(&capa_lock);
                if (rc == -ENOENT) {
                        DEBUG_CAPA(D_SEC, &ocapa->c_capa,
                                   "renewal canceled because object removed");
                        ll_capa_renewal_noent++;
                } else {
                        ll_capa_renewal_failed++;

                        /* failed capa won't be renewed any longer, but if -EIO,
                         * client might be doing recovery, retry in 2 min. */
                        if (rc == -EIO && !capa_is_expired(ocapa)) {
                                delay_capa_renew(ocapa, 120);
                                DEBUG_CAPA(D_ERROR, &ocapa->c_capa,
                                           "renewal failed: -EIO, retry in 2 mins");
                                ll_capa_renewal_retries++;
                                GOTO(retry, rc);
                        } else {
                                DEBUG_CAPA(D_ERROR, &ocapa->c_capa,
                                           "renewal failed(rc: %d) for", rc);
                        }
                }

                cfs_list_del_init(&ocapa->c_list);
                sort_add_capa(ocapa, &ll_idle_capas);
                cfs_spin_unlock(&capa_lock);

                capa_put(ocapa);
                iput(inode);
                RETURN(rc);
        }

        cfs_spin_lock(&ocapa->c_lock);
        LASSERT(!memcmp(&ocapa->c_capa, capa,
                        offsetof(struct lustre_capa, lc_opc)));
        ocapa->c_capa = *capa;
        set_capa_expiry(ocapa);
        cfs_spin_unlock(&ocapa->c_lock);

        cfs_spin_lock(&capa_lock);
        if (capa_for_oss(capa))
                inode_add_oss_capa(inode, ocapa);
        DEBUG_CAPA(D_SEC, capa, "renew");
        EXIT;
retry:
        cfs_list_del_init(&ocapa->c_list);
        sort_add_capa(ocapa, ll_capa_list);
        update_capa_timer(ocapa, capa_renewal_time(ocapa));
        cfs_spin_unlock(&capa_lock);

        capa_put(ocapa);
        iput(inode);
        return rc;
}

void ll_capa_open(struct inode *inode)
{
        struct ll_inode_info *lli = ll_i2info(inode);

        if ((ll_i2sbi(inode)->ll_flags & (LL_SBI_MDS_CAPA | LL_SBI_OSS_CAPA))
            == 0)
                return;

        if (!S_ISREG(inode->i_mode))
                return;

        cfs_atomic_inc(&lli->lli_open_count);
}

void ll_capa_close(struct inode *inode)
{
        struct ll_inode_info *lli = ll_i2info(inode);

        if ((ll_i2sbi(inode)->ll_flags & (LL_SBI_MDS_CAPA | LL_SBI_OSS_CAPA))
            == 0)
                return;

        if (!S_ISREG(inode->i_mode))
                return;

        cfs_atomic_dec(&lli->lli_open_count);
}

/* delete CAPA_OPC_OSS_TRUNC only */
void ll_truncate_free_capa(struct obd_capa *ocapa)
{
        if (!ocapa)
                return;

        LASSERT(ocapa->c_capa.lc_opc & CAPA_OPC_OSS_TRUNC);
        DEBUG_CAPA(D_SEC, &ocapa->c_capa, "free truncate");

        /* release ref when find */
        capa_put(ocapa);
        if (likely(ocapa->c_capa.lc_opc == CAPA_OPC_OSS_TRUNC)) {
                cfs_spin_lock(&capa_lock);
                ll_delete_capa(ocapa);
                cfs_spin_unlock(&capa_lock);
        }
}

void ll_clear_inode_capas(struct inode *inode)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct obd_capa *ocapa, *tmp;

        cfs_spin_lock(&capa_lock);
        ocapa = lli->lli_mds_capa;
        if (ocapa)
                ll_delete_capa(ocapa);

        cfs_list_for_each_entry_safe(ocapa, tmp, &lli->lli_oss_capas,
                                     u.cli.lli_list)
                ll_delete_capa(ocapa);
        cfs_spin_unlock(&capa_lock);
}

void ll_print_capa_stat(struct ll_sb_info *sbi)
{
        if (sbi->ll_flags & (LL_SBI_MDS_CAPA | LL_SBI_OSS_CAPA))
                LCONSOLE_INFO("Fid capabilities renewed: %llu\n"
                              "Fid capabilities renewal ENOENT: %llu\n"
                              "Fid capabilities failed to renew: %llu\n"
                              "Fid capabilities renewal retries: %llu\n",
                              ll_capa_renewed, ll_capa_renewal_noent,
                              ll_capa_renewal_failed, ll_capa_renewal_retries);
}
