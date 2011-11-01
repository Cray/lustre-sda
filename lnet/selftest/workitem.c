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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/selftest/workitem.c
 *
 * Author: Isaac Huang <isaac@clusterfs.com>
 */
#define DEBUG_SUBSYSTEM S_LNET

#include "selftest.h"

typedef struct swi_sched {
#ifdef __KERNEL__
        /** serialised workitems */
        spinlock_t        ws_lock;
        /** where schedulers sleep */
        cfs_waitq_t       ws_waitq;
#endif
        /** concurrent workitems */
        struct list_head  ws_runq;
        /** rescheduled running-workitems */
        struct list_head  ws_rerunq;
        /** shutting down */
        int               ws_shuttingdown;
} swi_sched_t;

#ifdef __KERNEL__
#define CFS_WI_NSCHED  (num_possible_cpus() + 1)
#else
/** always 2 for userspace */
#define CFS_WI_NSCHED   2
#endif /* __KERNEL__ */

struct smoketest_workitem {
        /** serialize */
        spinlock_t      wi_glock;
        /** number of swi_sched_t */
        int             wi_nsched;
        /** number of threads (all schedulers) */
        int             wi_nthreads;
        /** default scheduler */
        swi_sched_t    *wi_scheds;
} swi_data;

static inline swi_sched_t *
swi_to_sched(swi_workitem_t *wi)
{
        LASSERT(wi->wi_sched_id == CFS_WI_SCHED_SERIAL ||
                wi->wi_sched_id >= 0);

        return (wi->wi_sched_id == CFS_WI_SCHED_SERIAL) ?
               &swi_data.wi_scheds[swi_data.wi_nsched - 1] :
               &swi_data.wi_scheds[wi->wi_sched_id % (swi_data.wi_nsched - 1)];
}

#ifdef __KERNEL__
static inline void
swi_sched_lock(swi_sched_t *sched)
{
        spin_lock(&sched->ws_lock);
}

static inline void
swi_sched_unlock(swi_sched_t *sched)
{
        spin_unlock(&sched->ws_lock);
}

static inline int
swi_sched_cansleep(swi_sched_t *sched)
{
        swi_sched_lock(sched);
        if (sched->ws_shuttingdown) {
                swi_sched_unlock(sched);
                return 0;
        }

        if (!list_empty(&sched->ws_runq)) {
                swi_sched_unlock(sched);
                return 0;
        }
        swi_sched_unlock(sched);
        return 1;
}

#else

static inline void
swi_sched_lock(swi_sched_t *sched)
{
        spin_lock(&swi_data.wi_glock);
}

static inline void
swi_sched_unlock(swi_sched_t *sched)
{
        spin_unlock(&swi_data.wi_glock);
}

#endif

/* XXX: 
 * 0. it only works when called from wi->wi_action.
 * 1. when it returns no one shall try to schedule the workitem.
 */
void
swi_exit(swi_workitem_t *wi)
{
        swi_sched_t *sched = swi_to_sched(wi);

        LASSERT (!in_interrupt()); /* because we use plain spinlock */
        LASSERT (!sched->ws_shuttingdown);

        swi_sched_lock(sched);

#ifdef __KERNEL__
        LASSERT (wi->wi_running);
#endif
        if (wi->wi_scheduled) { /* cancel pending schedules */
                LASSERT (!list_empty(&wi->wi_list));
                list_del_init(&wi->wi_list);
        }

        LASSERT (list_empty(&wi->wi_list));
        wi->wi_scheduled = 1; /* LBUG future schedule attempts */

        swi_sched_unlock(sched);
        return;
}

/**
 * cancel a workitem:
 */
int
swi_cancel (swi_workitem_t *wi)
{
        swi_sched_t    *sched = swi_to_sched(wi);
        int             rc;

        LASSERT (!in_interrupt()); /* because we use plain spinlock */
        LASSERT (!sched->ws_shuttingdown);

        swi_sched_lock(sched);
        /*
         * return 0 if it's running already, otherwise return 1, which
         * means the workitem will not be scheduled and will not have
         * any race with wi_action.
         */
        rc = !(wi->wi_running);

        if (wi->wi_scheduled) { /* cancel pending schedules */
                LASSERT (!list_empty(&wi->wi_list));
                list_del_init(&wi->wi_list);
                wi->wi_scheduled = 0;
        }

        LASSERT (list_empty(&wi->wi_list));

        swi_sched_unlock(sched);
        return rc;
}

/*
 * Workitem scheduled with (serial == 1) is strictly serialised not only with
 * itself, but also with others scheduled this way.
 *
 * Now there's only one static serialised queue, but in the future more might
 * be added, and even dynamic creation of serialised queues might be supported.
 */
void
swi_schedule(swi_workitem_t *wi)
{
        swi_sched_t *sched = swi_to_sched(wi);

        LASSERT (!in_interrupt()); /* because we use plain spinlock */
        LASSERT (!sched->ws_shuttingdown);

        swi_sched_lock(sched);

        if (!wi->wi_scheduled) {
                LASSERT (list_empty(&wi->wi_list));

                wi->wi_scheduled = 1;
                if (!wi->wi_running) {
                        list_add_tail(&wi->wi_list, &sched->ws_runq);
#ifdef __KERNEL__
                        cfs_waitq_signal(&sched->ws_waitq);
#endif
                } else {
                        list_add(&wi->wi_list, &sched->ws_rerunq);
                }
        }

        LASSERT (!list_empty(&wi->wi_list));
        swi_sched_unlock(sched);
        return;
}

#ifdef __KERNEL__

static int
swi_scheduler (void *arg)
{
        int             id     = (int)(unsigned long) arg;
        int             serial = (id == swi_data.wi_nsched - 1);
        char            name[24];
        swi_sched_t    *sched;

        sched = &swi_data.wi_scheds[id];
        if (serial) {
                cfs_daemonize("wi_serial_sd");
        } else {
                /* will be sched = &swi_data.wi_scheds[id] in the future */
                snprintf(name, sizeof(name), "swi_sd%03d", id);
                cfs_daemonize(name);
        }

        cfs_block_allsigs();

        swi_sched_lock(sched);

        while (!sched->ws_shuttingdown) {
                int             nloops = 0;
                int             rc;
                swi_workitem_t *wi;

                while (!list_empty(&sched->ws_runq) &&
                       nloops < SWI_RESCHED) {
                        wi = list_entry(sched->ws_runq.next,
                                        swi_workitem_t, wi_list);

                        LASSERT (wi->wi_scheduled && !wi->wi_running);

                        list_del_init(&wi->wi_list);

                        wi->wi_running   = 1;
                        wi->wi_scheduled = 0;
                        swi_sched_unlock(sched);
                        nloops++;

                        rc = (*wi->wi_action) (wi);

                        swi_sched_lock(sched);
                        if (rc != 0) /* workitem should be dead, even be freed! */
                                continue;

                        wi->wi_running = 0;
                        if (list_empty(&wi->wi_list))
                                continue;

                        LASSERT (wi->wi_scheduled);
                        /* wi is rescheduled, should be on rerunq now, we
                         * move it to runq so it can run action now */
                        list_move_tail(&wi->wi_list, &sched->ws_runq);
                }

                if (!list_empty(&sched->ws_runq)) {
                        swi_sched_unlock(sched);
                        /* don't sleep because some workitems still
                         * expect me to come back soon */
                        cfs_cond_resched();
                        swi_sched_lock(sched);
                        continue;
                }

                swi_sched_unlock(sched);
                cfs_wait_event_interruptible_exclusive(sched->ws_waitq,
                                !swi_sched_cansleep(sched), rc);
                swi_sched_lock(sched);
        }

        swi_sched_unlock(sched);

        spin_lock(&swi_data.wi_glock);
        swi_data.wi_nthreads--;
        spin_unlock(&swi_data.wi_glock);
        return 0;
}

int
swi_start_thread (int (*func) (void*), void *arg)
{
        long pid;

        pid = cfs_kernel_thread(func, arg, 0);
        if (pid < 0)
                return (int)pid;

        spin_lock(&swi_data.wi_glock);
        swi_data.wi_nthreads++;
        spin_unlock(&swi_data.wi_glock);
        return 0;
}

#else /* __KERNEL__ */

int
swi_check_events (void)
{
        int               n = 0;
        swi_workitem_t   *wi;
        struct list_head *q;

        spin_lock(&swi_data.wi_glock);

        for (;;) {
                /** rerunq is always empty for userspace */
                if (!list_empty(&swi_data.wi_scheds[1].ws_runq))
                        q = &swi_data.wi_scheds[1].ws_runq;
                else if (!list_empty(&swi_data.wi_scheds[0].ws_runq))
                        q = &swi_data.wi_scheds[0].ws_runq;
                else
                        break;

                wi = list_entry(q->next, swi_workitem_t, wi_list);
                list_del_init(&wi->wi_list);

                LASSERT (wi->wi_scheduled);
                wi->wi_scheduled = 0;
                spin_unlock(&swi_data.wi_glock);

                n++;
                (*wi->wi_action) (wi);

                spin_lock(&swi_data.wi_glock);
        }

        spin_unlock(&swi_data.wi_glock);
        return n;
}

#endif

static void
swi_sched_init(swi_sched_t *sched)
{
        sched->ws_shuttingdown = 0;
#ifdef __KERNEL__
        spin_lock_init(&sched->ws_lock);
        cfs_waitq_init(&sched->ws_waitq);
#endif
        CFS_INIT_LIST_HEAD(&sched->ws_runq);
        CFS_INIT_LIST_HEAD(&sched->ws_rerunq);
}

static void
swi_sched_shutdown(swi_sched_t *sched)
{
        swi_sched_lock(sched);

        LASSERT(list_empty(&sched->ws_runq));
        LASSERT(list_empty(&sched->ws_rerunq));

        sched->ws_shuttingdown = 1;

#ifdef __KERNEL__
        cfs_waitq_broadcast(&sched->ws_waitq);
#endif
        swi_sched_unlock(sched);
}


int
swi_startup (void)
{
        int i;
        int rc;

        swi_data.wi_nthreads = 0;
        swi_data.wi_nsched   = CFS_WI_NSCHED;
        LIBCFS_ALLOC(swi_data.wi_scheds,
                     swi_data.wi_nsched * sizeof(swi_sched_t));
        if (swi_data.wi_scheds == NULL)
                return -ENOMEM;

        spin_lock_init(&swi_data.wi_glock);
        for (i = 0; i < swi_data.wi_nsched; i++)
                swi_sched_init(&swi_data.wi_scheds[i]);

#ifdef __KERNEL__
        for (i = 0; i < swi_data.wi_nsched ; i++) {
                rc = swi_start_thread(swi_scheduler, (void *)(unsigned long)i);
                if (rc != 0) {
                        CERROR ("Can't spawn workitem scheduler: %d\n", rc);
                        swi_shutdown();
                        return rc;
                }
        }
#else
        rc = 0;
#endif

        return 0;
}

void
swi_shutdown (void)
{
        int i;

        if (swi_data.wi_scheds == NULL)
                return;

        for (i = 0; i < swi_data.wi_nsched; i++)
                swi_sched_shutdown(&swi_data.wi_scheds[i]);

#ifdef __KERNEL__
        spin_lock(&swi_data.wi_glock);
        i = 2;
        while (swi_data.wi_nthreads != 0) {
                CDEBUG(IS_PO2(++i) ? D_WARNING : D_NET,
                       "waiting for %d threads to terminate\n",
                       swi_data.wi_nthreads);
                spin_unlock(&swi_data.wi_glock);

                cfs_pause(cfs_time_seconds(1));

                spin_lock(&swi_data.wi_glock);
        }
        spin_unlock(&swi_data.wi_glock);
#endif
        LIBCFS_FREE(swi_data.wi_scheds,
                    swi_data.wi_nsched * sizeof(swi_sched_t));
        return;
}
