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
 */

#ifndef _LIBCFS_FAIL_H
#define _LIBCFS_FAIL_H

extern unsigned int cfs_fail_loc;
extern unsigned int cfs_fail_val;

extern cfs_waitq_t cfs_race_waitq;
extern int cfs_race_state;

/* LNet is allocated failure locations 0xe000 to 0xffff */

/* GNILND has 0xf0XX */
#define CFS_FAIL_GNI                    0xf000
#define CFS_FAIL_GNI_PHYS_MAP           0xf001
#define CFS_FAIL_GNI_VIRT_MAP           0xf002
#define CFS_FAIL_GNI_GET_UNMAP          0xf003
#define CFS_FAIL_GNI_PUT_UNMAP          0xf004
#define CFS_FAIL_GNI_MAP_TX             0xf005
#define CFS_FAIL_GNI_SMSG_SEND          0xf006
#define CFS_FAIL_GNI_CLOSE_SEND         0xf007
#define CFS_FAIL_GNI_CDM_CREATE         0xf008
#define CFS_FAIL_GNI_CDM_DESTROY        0xf009
#define CFS_FAIL_GNI_CDM_ATTACH         0xf00a
#define CFS_FAIL_GNI_CQ_CREATE          0xf00b
#define CFS_FAIL_GNI_CQ_DESTROY         0xf00c
#define CFS_FAIL_GNI_EP_BIND            0xf00d
#define CFS_FAIL_GNI_EP_UNBIND          0xf00e
#define CFS_FAIL_GNI_EP_SET_EVDATA      0xf00f
#define CFS_FAIL_GNI_SMSG_INIT          0xf010
#define CFS_FAIL_GNI_SMSG_RELEASE       0xf011
#define CFS_FAIL_GNI_POST_RDMA          0xf012
#define CFS_FAIL_GNI_GET_COMPLETED      0xf013
#define CFS_FAIL_GNI_EP_DESTROY         0xf015
#define CFS_FAIL_GNI_VIRT_UNMAP         0xf016
#define CFS_FAIL_GNI_MDD_RELEASE        0xf017
#define CFS_FAIL_GNI_NOOP_SEND          0xf018
#define CFS_FAIL_GNI_ERR_SUBSCRIBE      0xf01a
#define CFS_FAIL_GNI_QUIESCE_RACE       0xf01b
#define CFS_FAIL_GNI_DG_TERMINATE       0xf01c
#define CFS_FAIL_GNI_REG_QUIESCE        0xf01d
#define CFS_FAIL_GNI_IN_QUIESCE         0xf01e
#define CFS_FAIL_GNI_DELAY_RDMA         0xf01f
#define CFS_FAIL_GNI_SR_DOWN_RACE       0xf020
#define CFS_FAIL_GNI_ALLOC_TX           0xf021
#define CFS_FAIL_GNI_FMABLK_AVAIL       0xf022
#define CFS_FAIL_GNI_EP_CREATE          0xf023
#define CFS_FAIL_GNI_CQ_GET_EVENT       0xf024
#define CFS_FAIL_GNI_PROBE              0xf025
#define CFS_FAIL_GNI_EP_TEST            0xf026
#define CFS_FAIL_GNI_CONNREQ_DROP       0xf027
#define CFS_FAIL_GNI_CONNREQ_PROTO      0xf028
#define CFS_FAIL_GNI_CONND_PILEUP       0xf029
#define CFS_FAIL_GNI_PHYS_SETUP         0xf02a
#define CFS_FAIL_GNI_FIND_TARGET        0xf02b
#define CFS_FAIL_GNI_WC_DGRAM_FREE      0xf02c
#define CFS_FAIL_GNI_DROP_CLOSING       0xf02d
#define CFS_FAIL_GNI_RX_CLOSE_CLOSING   0xf02e
#define CFS_FAIL_GNI_RX_CLOSE_CLOSED    0xf02f
#define CFS_FAIL_GNI_EP_POST            0xf030
#define CFS_FAIL_GNI_PACK_SRCNID        0xf031
#define CFS_FAIL_GNI_PACK_DSTNID        0xf032
#define CFS_FAIL_GNI_PROBE_WAIT         0xf033
#define CFS_FAIL_GNI_SMSG_CKSUM1        0xf034
#define CFS_FAIL_GNI_SMSG_CKSUM2        0xf035
#define CFS_FAIL_GNI_SMSG_CKSUM3        0xf036
#define CFS_FAIL_GNI_DROP_DESTROY_EP    0xf037
#define CFS_FAIL_GNI_SMSG_GETNEXT       0xf038
#define CFS_FAIL_GNI_FINISH_PURG        0xf039
#define CFS_FAIL_GNI_PURG_REL_DELAY     0xf03a
#define CFS_FAIL_GNI_DONT_NOTIFY        0xf03b
#define CFS_FAIL_GNI_VIRT_SMALL_MAP     0xf03c
#define CFS_FAIL_GNI_DELAY_RDMAQ        0xf03d

/* Failure injection control */
#define CFS_FAIL_MASK_SYS    0x0000FF00
#define CFS_FAIL_MASK_LOC   (0x000000FF | CFS_FAIL_MASK_SYS)
#define CFS_FAIL_ONCE        0x80000000
#define CFS_FAILED           0x40000000
/* The following flags aren't made to be combined */
#define CFS_FAIL_SKIP        0x20000000 /* skip N then fail */
#define CFS_FAIL_SOME        0x10000000 /* fail N times */
#define CFS_FAIL_RAND        0x08000000 /* fail 1/N of the time */
#define CFS_FAIL_USR1        0x04000000 /* user flag */

int cfs_fail_check(__u32 id);
#define CFS_FAIL_CHECK(id)                                                   \
({                                                                           \
        int _ret_ = 0;                                                       \
        if (unlikely(cfs_fail_loc && (_ret_ = cfs_fail_check(id)))) {        \
                CERROR("*** cfs_fail_loc=%x ***\n", id);                     \
        }                                                                    \
        _ret_;                                                               \
})

#define CFS_FAIL_CHECK_QUIET(id)                                             \
        (unlikely(cfs_fail_loc) ? cfs_fail_check(id) : 0)

#define CFS_FAIL_RETURN(id, ret)                                             \
do {                                                                         \
        if (unlikely(cfs_fail_loc && cfs_fail_check(id))) {                  \
                CERROR("*** cfs_fail_return=%x rc=%d ***\n", id, ret);       \
                RETURN(ret);                                                 \
        }                                                                    \
} while(0)

#define CFS_FAIL_TIMEOUT(id, secs)                                           \
({      int _ret_ = 0;                                                       \
        if (unlikely(cfs_fail_loc && (_ret_ = cfs_fail_check(id)))) {        \
                CERROR("cfs_fail_timeout id %x sleeping for %d secs\n",      \
                       (id), (secs));                                        \
                cfs_schedule_timeout(CFS_TASK_UNINT,                         \
                                    cfs_time_seconds(secs));                 \
                CERROR("cfs_fail_timeout id %x awake\n", (id));              \
        }                                                                    \
        _ret_;                                                               \
})

#define CFS_FAIL_TIMEOUT_MS(id, ms)                                          \
({      int _ret_ = 0;                                                       \
        if (unlikely(cfs_fail_loc && (_ret_ = cfs_fail_check(id)))) {        \
                CERROR("cfs_fail_timeout id %x sleeping for %d ms\n",        \
                       (id), (ms));                                          \
                cfs_schedule_timeout(CFS_TASK_UNINT,                         \
                                     cfs_time_seconds(ms)/1000);             \
                CERROR("cfs_fail_timeout id %x awake\n", (id));              \
        }                                                                    \
        _ret_;                                                               \
})

#ifdef __KERNEL__
/* The idea here is to synchronise two threads to force a race. The
 * first thread that calls this with a matching fail_loc is put to
 * sleep. The next thread that calls with the same fail_loc wakes up
 * the first and continues. */
#define CFS_RACE(id)                                                         \
do {                                                                         \
        if (unlikely(cfs_fail_loc && cfs_fail_check(id))) {                  \
                cfs_race_state = 0;                                          \
                CERROR("cfs_race id %x sleeping\n", (id));                   \
                CFS_SLEEP_ON(cfs_race_waitq, cfs_race_state != 0);           \
                CERROR("cfs_fail_race id %x awake\n", (id));                 \
        } else if ((cfs_fail_loc & CFS_FAIL_MASK_LOC) ==                     \
                    ((id) & CFS_FAIL_MASK_LOC)) {                            \
                CERROR("cfs_fail_race id %x waking\n", (id));                \
                cfs_race_state = 1;                                          \
                wake_up(&cfs_race_waitq);                                    \
        }                                                                    \
} while(0)
#else
/* sigh.  an expedient fix until CFS_RACE is fixed up */
#define CFS_RACE(foo) do {} while(0)
#endif

/* Rather than create one-liner .h files, just define here */
#if defined(__linux__)
#define CFS_SLEEP_ON(wq, state)  wait_event_interruptible(wq, state)
#elif defined(__APPLE__)
#define CFS_SLEEP_ON(wq)        sleep_on(wq)
#error Unsupported operating system.
#endif

#endif /* _LIBCFS_FAIL_H */

