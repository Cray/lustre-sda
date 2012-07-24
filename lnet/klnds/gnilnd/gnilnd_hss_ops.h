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
#ifndef _GNILND_HSS_OPS_H
#define _GNILND_HSS_OPS_H

/* for krca nid & nic translation */
#include <krca_lib.h>
#include <linux/typecheck.h>

typedef struct kgn_hssops
{ 
        /* function pointers for nid and nic conversion */
        /* from krca_lib.h */
        int     (*nid_to_nicaddr)(__u32 nid, int numnic, __u32 *nicaddr);
        int     (*nicaddr_to_nid)(__u32 nicaddr, __u32 *nid);
        void    (*hb_to_l0)(void);
} kgn_hssops_t;

/* pull in static store in gnilnd.c */
extern kgn_hssops_t             kgnilnd_hssops;

#define GNILND_NO_RCA           0xdeadbeef
#define GNILND_NO_QUIESCE       0xdeadbeef

static inline int
kgnilnd_lookup_rca_funcs(void)
{
        void    *funcp;

        funcp = __symbol_get("send_hb_2_l0");
        if (funcp != 0) {
                kgnilnd_hssops.hb_to_l0 = funcp;
        }

        /* if we find one, we should get the other */

        funcp = __symbol_get("krca_nid_to_nicaddrs");
        if (funcp == 0) {
                kgnilnd_hssops.nid_to_nicaddr = (void *)GNILND_NO_RCA;
                kgnilnd_hssops.nicaddr_to_nid = (void *)GNILND_NO_RCA;
                return 0;
        }
        kgnilnd_hssops.nid_to_nicaddr = funcp;

        funcp = __symbol_get("krca_nicaddr_to_nid");
        if (funcp == 0) {
                CERROR("found krca_nid_to_nicaddrs but not krca_nicaddr_to_nid\n");
                return -ESRCH;
        }
        kgnilnd_hssops.nicaddr_to_nid = funcp;

        return 0;
}

/* we use RCA types here to get the compiler to whine when we have 
 * mismatched types */
static inline int
kgnilnd_nid_to_nicaddrs(rca_nid_t nid, int numnic, nic_addr_t *nicaddrs)
{
        /* compile time checks to ensure that the RCA types match 
         * the LNet idea of NID and NIC */
        typecheck(__u32, nid);
        typecheck(__u32, *nicaddrs);

        LASSERTF(kgnilnd_hssops.nid_to_nicaddr != NULL, "missing setup?\n");

        return kgnilnd_hssops.nid_to_nicaddr(nid, numnic, nicaddrs);
}

static inline int
kgnilnd_nicaddr_to_nid(nic_addr_t nicaddr, rca_nid_t *nid)
{
        /* compile time checks to ensure that the RCA types match 
         * the LNet idea of NID and NIC */
        typecheck(__u32, nicaddr);
        typecheck(__u32, nid[0]);

        LASSERTF(kgnilnd_hssops.nicaddr_to_nid != NULL, "missing setup ?\n");

        return kgnilnd_hssops.nicaddr_to_nid(nicaddr, nid);
}

#endif /* _GNILND_HSS_OPS_H */
