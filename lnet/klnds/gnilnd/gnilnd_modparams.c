/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2004 Cluster File Systems, Inc.
 *   Author: Eric Barton <eric@bartonsoftware.com>
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include "gnilnd.h"

static int credits = 256;
CFS_MODULE_PARM(credits, "i", int, 0444,
                "# concurrent sends");

static int peer_credits = 16;
CFS_MODULE_PARM(peer_credits, "i", int, 0444,
                "# concurrent sends to 1 peer");

/* default for 2k nodes @ 16 peer credits */
static int fma_cq_size = 32768;
CFS_MODULE_PARM(fma_cq_size, "i", int, 0444,
                "size of the completion queue");

static int timeout = GNILND_BASE_TIMEOUT;
/* can't change @ runtime because LNet gets NI data at startup from 
 * this value */
CFS_MODULE_PARM(timeout, "i", int, 0444,
                "communications timeout (seconds)");

/* time to wait between datagram timeout and sending of next dgram */
static int min_reconnect_interval = GNILND_MIN_RECONNECT_TO;
CFS_MODULE_PARM(min_reconnect_interval, "i", int, 0644,
                "minimum connection retry interval (seconds)");

/* if this goes longer than timeout, we'll timeout the TX before
 * the dgram */
static int max_reconnect_interval = GNILND_MAX_RECONNECT_TO;
CFS_MODULE_PARM(max_reconnect_interval, "i", int, 0644,
                "maximum connection retry interval (seconds)");

static int max_immediate = (2<<10);
CFS_MODULE_PARM(max_immediate, "i", int, 0644,
                "immediate/RDMA breakpoint");

#ifdef CONFIG_CRAY_GEMINI
static int checksum = 3;
#else
static int checksum = 0;
#endif
CFS_MODULE_PARM(checksum, "i", int, 0644,
                "0: None, 1: headers, 2: short msg, 3: all traffic");

static int checksum_dump = 0;
CFS_MODULE_PARM(checksum_dump, "i", int, 0644,
                "0: None, 1: dump log on failure, 2: payload data to D_INFO log");

static int bte_hash = 1;
CFS_MODULE_PARM(bte_hash, "i", int, 0644,
                "enable hashing for BTE (RDMA) transfers");

static int bte_adapt = 1;
CFS_MODULE_PARM(bte_adapt, "i", int, 0644,
                "enable adaptive request and response for BTE (RDMA) transfers");

static int bte_relaxed_ordering = 1;
CFS_MODULE_PARM(bte_relaxed_ordering, "i", int, 0644,
                "enable relaxed ordering (PASSPW) for BTE (RDMA) transfers");

static int ptag = GNI_PTAG_LND;
CFS_MODULE_PARM(ptag, "i", int, 0444,
                "ptag for Gemini CDM");

static int max_retransmits = 1024;
CFS_MODULE_PARM(max_retransmits, "i", int, 0644,
                "max retransmits for FMA");

static int nwildcard = 4;
CFS_MODULE_PARM(nwildcard, "i", int, 0444,
                "# wildcard datagrams to post per net (interface)");

static int nice = -20;
CFS_MODULE_PARM(nice, "i", int, 0444,
                "nice value for kgnilnd threads, default -20");

static int rdmaq_intervals = 4;
CFS_MODULE_PARM(rdmaq_intervals, "i", int, 0644,
                "# intervals per second for rdmaq throttling, default 4, 0 to disable");

static int loops = 100;
CFS_MODULE_PARM(loops, "i", int, 0644,
                "# of loops before scheduler is friendly, default 100");

static int hash_size = 503;
CFS_MODULE_PARM(hash_size, "i", int, 0444,
                "prime number for peer/conn hash sizing, default 503");

static int peer_health = 0;
CFS_MODULE_PARM(peer_health, "i", int, 0444,
                "Disable peer timeout for LNet peer health, default off, > 0 to enable");

static int vmap_cksum = 0;
CFS_MODULE_PARM(vmap_cksum, "i", int, 0644,
                "use vmap for all kiov checksumming, default off");

/* this is an optimization for service nodes where they could be
 * seeing 10k+ conns/mailboxes */
#if defined(CONFIG_CRAY_COMPUTE)
static int mbox_per_block = 64;
#else
static int mbox_per_block = GNILND_FMABLK_MAX;
#endif
CFS_MODULE_PARM(mbox_per_block, "i", int, 0644,
                "mailboxes per block");

static int mbox_credits = GNILND_MBOX_CREDITS;
CFS_MODULE_PARM(mbox_credits, "i", int, 0644,
                "number of credits per mailbox");

kgn_tunables_t kgnilnd_tunables = {
        .kgn_min_reconnect_interval = &min_reconnect_interval,
        .kgn_max_reconnect_interval = &max_reconnect_interval,
        .kgn_credits                = &credits,
        .kgn_peer_credits           = &peer_credits,
        .kgn_fma_cq_size            = &fma_cq_size,
        .kgn_timeout                = &timeout,
        .kgn_max_immediate          = &max_immediate,
        .kgn_checksum               = &checksum,
        .kgn_checksum_dump          = &checksum_dump,
        .kgn_bte_hash               = &bte_hash,
        .kgn_bte_adapt              = &bte_adapt,
        .kgn_bte_relaxed_ordering   = &bte_relaxed_ordering,
        .kgn_ptag                   = &ptag,
        .kgn_max_retransmits        = &max_retransmits,
        .kgn_nwildcard              = &nwildcard,
        .kgn_nice                   = &nice,
        .kgn_rdmaq_intervals        = &rdmaq_intervals,
        .kgn_loops                  = &loops,
        .kgn_peer_hash_size         = &hash_size,
        .kgn_peer_health            = &peer_health,
        .kgn_vmap_cksum             = &vmap_cksum,
        .kgn_mbox_per_block         = &mbox_per_block,
        .kgn_mbox_credits           = &mbox_credits
};

#if CONFIG_SYSCTL && !CFS_SYSFS_MODULE_PARM
static cfs_sysctl_table_t kgnilnd_ctl_table[] = {
        {
                .ctl_name = 2,
                .procname = "min_reconnect_interval",
                .data     = &min_reconnect_interval,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 3,
                .procname = "max_reconnect_interval",
                .data     = &max_reconnect_interval,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 5,
                .procname = "credits",
                .data     = &credits,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 6,
                .procname = "peer_credits",
                .data     = &peer_credits,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 7,
                .procname = "fma_cq_size",
                .data     = &fma_cq_size,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 8,
                .procname = "timeout",
                .data     = &timeout,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 9,
                .procname = "max_immediate",
                .data     = &max_immediate,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 10,
                .procname = "checksum",
                .data     = &checksum,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 11,
                .procname = "bte_hash",
                .data     = &bte_hash,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 12,
                .procname = "bte_adapt",
                .data     = &bte_adapt,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 13,
                .procname = "ptag",
                .data     = &ptag,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 14,
                .procname = "nwildcard",
                .data     = &nwildcard,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 15,
                .procname = "bte_relaxed_ordering",
                .data     = &bte_relaxed_ordering,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 16,
                .procname = "checksum_dump",
                .data     = &checksum_dump,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 17,
                .procname = "nice",
                .data     = &nice,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 18,
                .procname = "rdmaq_intervals",
                .data     = &rdmaq_intervals,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 19,
                .procname = "loops",
                .data     = &loops,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 20,
                .procname = "hash_size",
                .data     = &hash_size,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 21,
                .procname = "peer_health",
                .data     = &peer_health,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 22,
                .procname = "vmap_cksum",
                .data     = &vmap_cksum,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 23,
                .procname = "mbox_per_block",
                .data     = &mbox_per_block,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 24,
                .procname = "mbox_credits"
                .data     = &mbox_credits,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {0}
};

static cfs_sysctl_table_t kgnilnd_top_ctl_table[] = {
        {
                .ctl_name = 202,
                .procname = "gnilnd",
                .data     = NULL,
                .maxlen   = 0,
                .mode     = 0555,
                .child    = kgnilnd_ctl_table
        },
        {0}
};

int
kgnilnd_tunables_init ()
{
        kgnilnd_tunables.kgn_sysctl =
                cfs_register_sysctl_table(kgnilnd_top_ctl_table, 0);

        if (kgnilnd_tunables.kgn_sysctl == NULL)
                CWARN("Can't setup /proc tunables\n");

        return 0;
}

void
kgnilnd_tunables_fini ()
{
        if (kgnilnd_tunables.kgn_sysctl != NULL)
                cfs_unregister_sysctl_table(kgnilnd_tunables.kgn_sysctl);
}

#else

int
kgnilnd_tunables_init ()
{
        return 0;
}

void
kgnilnd_tunables_fini ()
{
}

#endif

