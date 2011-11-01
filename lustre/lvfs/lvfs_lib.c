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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/lvfs/lvfs_lib.c
 *
 * Lustre filesystem abstraction routines
 *
 * Author: Andreas Dilger <adilger@clusterfs.com>
 */
#ifdef __KERNEL__
#include <linux/module.h>
#else
#include <liblustre.h>
#endif
#include <lustre_lib.h>
#include <lprocfs_status.h>

__u64 obd_max_pages = 0;
__u64 obd_max_alloc = 0;

#ifdef __KERNEL__
struct lprocfs_stats *obd_memory = NULL;
spinlock_t obd_updatemax_lock = SPIN_LOCK_UNLOCKED;
/* refine later and change to seqlock or simlar from libcfs */
#else
__u64 obd_alloc;
__u64 obd_pages;
#endif

unsigned int obd_alloc_fail_rate = 0;

int obd_alloc_fail(const void *ptr, const char *name, const char *type,
                   size_t size, const char *file, int line)
{
        if (ptr == NULL ||
            (cfs_rand() & OBD_ALLOC_FAIL_MASK) < obd_alloc_fail_rate) {
                CERROR("%s%salloc of %s ("LPU64" bytes) failed at %s:%d\n",
                       ptr ? "force " :"", type, name, (__u64)size, file,
                       line);
                CERROR(LPU64" total bytes and "LPU64" total pages "
                       "("LPU64" bytes) allocated by Lustre, "
                       "%d total bytes by LNET\n",
                       obd_memory_sum(),
                       obd_pages_sum() << CFS_PAGE_SHIFT,
                       obd_pages_sum(),
                       atomic_read(&libcfs_kmemory));
               return 1;
        }
        return 0;
}
EXPORT_SYMBOL(obd_alloc_fail);

#ifdef __KERNEL__
void obd_update_maxusage()
{
        __u64 max1, max2;

        max1 = obd_pages_sum();
        max2 = obd_memory_sum();

        spin_lock(&obd_updatemax_lock);
        if (max1 > obd_max_pages)
                obd_max_pages = max1;
        if (max2 > obd_max_alloc)
                obd_max_alloc = max2;
        spin_unlock(&obd_updatemax_lock);
}

__u64 obd_memory_max(void)
{
        __u64 ret;

        spin_lock(&obd_updatemax_lock);
        ret = obd_max_alloc;
        spin_unlock(&obd_updatemax_lock);

        return ret;
}

__u64 obd_pages_max(void)
{
        __u64 ret;

        spin_lock(&obd_updatemax_lock);
        ret = obd_max_pages;
        spin_unlock(&obd_updatemax_lock);

        return ret;
}

EXPORT_SYMBOL(obd_update_maxusage);
EXPORT_SYMBOL(obd_pages_max);
EXPORT_SYMBOL(obd_memory_max);
EXPORT_SYMBOL(obd_memory);

#endif

#ifdef LPROCFS
__s64 lprocfs_read_helper(struct lprocfs_counter *lc,
                          enum lprocfs_fields_flags field)
{
        __s64 ret = 0;
        int centry;

        if (!lc)
                RETURN(0);
        do {
                centry = atomic_read(&lc->lc_cntl.la_entry);

                switch (field) {
                        case LPROCFS_FIELDS_FLAGS_CONFIG:
                                ret = lc->lc_config;
                                break;
                        case LPROCFS_FIELDS_FLAGS_SUM:
                                ret = lc->lc_sum + lc->lc_sum_irq;
                                break;
                        case LPROCFS_FIELDS_FLAGS_MIN:
                                ret = lc->lc_min;
                                break;
                        case LPROCFS_FIELDS_FLAGS_MAX:
                                ret = lc->lc_max;
                                break;
                        case LPROCFS_FIELDS_FLAGS_AVG:
                                ret = (lc->lc_max - lc->lc_min)/2;
                                break;
                        case LPROCFS_FIELDS_FLAGS_SUMSQUARE:
                                ret = lc->lc_sumsquare;
                                break;
                        case LPROCFS_FIELDS_FLAGS_COUNT:
                                ret = lc->lc_count;
                                break;
                        default:
                                break;
                };
        } while (centry != atomic_read(&lc->lc_cntl.la_entry) &&
                 centry != atomic_read(&lc->lc_cntl.la_exit));

        RETURN(ret);
}
EXPORT_SYMBOL(lprocfs_read_helper);

void lprocfs_counter_add(struct lprocfs_stats *stats, int idx,
                                       long amount)
{
        struct lprocfs_counter *percpu_cntr;
        int smp_id;

        if (stats == NULL)
                return;

        /* With per-client stats, statistics are allocated only for
         * single CPU area, so the smp_id should be 0 always. */
        smp_id = lprocfs_stats_lock(stats, LPROCFS_GET_SMP_ID);

        percpu_cntr = &(stats->ls_percpu[smp_id]->lp_cntr[idx]);
        atomic_inc(&percpu_cntr->lc_cntl.la_entry);
        percpu_cntr->lc_count++;

        if (percpu_cntr->lc_config & LPROCFS_CNTR_AVGMINMAX) {
                /* see comment in lprocfs_counter_sub */
                LASSERT(!cfs_in_interrupt());

                percpu_cntr->lc_sum += amount;
                if (percpu_cntr->lc_config & LPROCFS_CNTR_STDDEV)
                        percpu_cntr->lc_sumsquare += (__u64)amount * amount;
                if (amount < percpu_cntr->lc_min)
                        percpu_cntr->lc_min = amount;
                if (amount > percpu_cntr->lc_max)
                        percpu_cntr->lc_max = amount;
        }
        atomic_inc(&percpu_cntr->lc_cntl.la_exit);
        lprocfs_stats_unlock(stats);
}
EXPORT_SYMBOL(lprocfs_counter_add);

void lprocfs_counter_sub(struct lprocfs_stats *stats, int idx,
                                       long amount)
{
        struct lprocfs_counter *percpu_cntr;
        int smp_id;

        if (stats == NULL)
                return;

        /* With per-client stats, statistics are allocated only for
         * single CPU area, so the smp_id should be 0 always. */
        smp_id = lprocfs_stats_lock(stats, LPROCFS_GET_SMP_ID);

        percpu_cntr = &(stats->ls_percpu[smp_id]->lp_cntr[idx]);
        atomic_inc(&percpu_cntr->lc_cntl.la_entry);
        if (percpu_cntr->lc_config & LPROCFS_CNTR_AVGMINMAX) {
                /*
                 * currently lprocfs_count_add() can only be called in thread
                 * context; sometimes we use RCU callbacks to free memory
                 * which calls lprocfs_counter_sub(), and RCU callbacks may
                 * execute in softirq context - right now that's the only case
                 * we're in softirq context here, use separate counter for that.
                 * bz20650.
                 */
                if (cfs_in_interrupt())
                        percpu_cntr->lc_sum_irq -= amount;
                else
                        percpu_cntr->lc_sum -= amount;
        }
        atomic_inc(&percpu_cntr->lc_cntl.la_exit);
        lprocfs_stats_unlock(stats);
}
EXPORT_SYMBOL(lprocfs_counter_sub);
#endif  /* LPROCFS */

EXPORT_SYMBOL(obd_alloc_fail_rate);
