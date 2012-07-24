/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2009-2012 Cray, Inc.
 *   Author: Nic Henke <nic@cray.com>, James Shimek <jshimek@cray.com>
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
#ifndef _GNILND_ARIES_H
#define _GNILND_ARIES_H

/* for krca nid & nic translation */
#include <krca_lib.h>
#include <linux/typecheck.h>

/* for libcfs_ipif_query */
#include <libcfs/libcfs.h>

#ifndef _GNILND_HSS_OPS_H
# error "must include gnilnd_hss_ops.h first"
#endif

/* Set HW related values */
#include <aries/aries_timeouts_gpl.h>

#define GNILND_BASE_TIMEOUT        TIMEOUT_SECS(TO_GNILND_timeout)
#define GNILND_CHECKSUM_DEFAULT    0            /* all off for Aries */

/* Aries Sim doesn't have hardcoded tables, so we'll hijack the nic_pe 
 * and decode our address and nic addr from that - the rest are just offsets */
static __u32 aries_sim_base_nid;
static __u32 aries_sim_nic;

static int
aries_nid_to_nicaddr(__u32 nid, int numnic, __u32 *nicaddr)
{
        if (numnic > 1) {
                CERROR("manual nid2nic translation doesn't support"
                       "multiple nic addrs (you asked for %d)\n",
                        numnic);
                return -EINVAL;
        }
        if (nid < aries_sim_base_nid) {
                CERROR("Request for invalid nid translation %u, minimum %u\n",
                       nid, aries_sim_base_nid);
                return -ESRCH;
        }

        *nicaddr = nid - aries_sim_base_nid;
        return 1;
}

static int
aries_nicaddr_to_nid(__u32 nicaddr, __u32 *nid)
{
        *nid = aries_sim_base_nid + nicaddr;
        return 1;
}

/* XXX Nic: This does not support multiple device!!!! */
static inline int
kgnilnd_setup_nic_translation(__u32 device_id)
{
        char              *if_name = "ipogif0";
        __u32              ipaddr, netmask, my_nid;
        int                up, rc;

        /* do lookup on first use */
        if (unlikely(kgnilnd_hssops.nid_to_nicaddr == NULL)) {
                rc = kgnilnd_lookup_rca_funcs();
                if (rc) 
                        return rc;
        }

        /* if we have a real function, return - we'll use those going forward */
        if (likely(kgnilnd_hssops.nid_to_nicaddr != (void *)GNILND_NO_RCA))
                return 0;

        LCONSOLE_INFO("using Aries SIM IP info for RCA translation\n");

        rc = libcfs_ipif_query(if_name, &up, &ipaddr, &netmask);
        if (rc != 0) {
                CERROR ("can't get IP interface for %s: %d\n", if_name, rc);
                return rc;
        }
        if (!up) {
                CERROR ("IP interface %s is down\n", if_name);
                return -ENODEV;
        }

        my_nid = ((ipaddr >> 8) & 0xFF) + (ipaddr & 0xFF);
        aries_sim_nic = device_id;
        aries_sim_base_nid = my_nid - aries_sim_nic;

        kgnilnd_hssops.nid_to_nicaddr = aries_nid_to_nicaddr;
        kgnilnd_hssops.nicaddr_to_nid = aries_nicaddr_to_nid;

        return 0;
}

#endif /* _GNILND_ARIES_H */
