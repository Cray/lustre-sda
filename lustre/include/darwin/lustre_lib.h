/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001 Cluster File Systems, Inc. <braam@clusterfs.com>
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
 * Basic Lustre library routines.
 *
 */

#ifndef _DARWIN_LUSTRE_LIB_H
#define _DARWIN_LUSTRE_LIB_H

#ifndef _LUSTRE_LIB_H
#error Do not #include this file directly. #include <lustre_lib.h> instead
#endif

#include <string.h>
#include <libcfs/libcfs.h>
#include <libcfs/kp30.h> 

#ifndef LP_POISON
#define LI_POISON ((int)0x5a5a5a5a)
#define LL_POISON ((long)0x5a5a5a5a)
#define LP_POISON ((void *)(long)0x5a5a5a5a)
#endif

#ifndef LPU64
#define LPU64 "%llu"
#define LPD64 "%lld"
#define LPX64 "%llx"
#endif

struct obd_ioctl_data;
#define OBD_IOC_DATA_TYPE               struct obd_ioctl_data

#define LUSTRE_FATAL_SIGS (sigmask(SIGKILL) | sigmask(SIGINT) |                \
                           sigmask(SIGTERM) | sigmask(SIGQUIT) |               \
                           sigmask(SIGALRM) | sigmask(SIGHUP))

#ifdef __KERNEL__
static inline sigset_t l_w_e_set_sigs(sigset_t sigs)
{
        struct proc     *p = current_proc();
        sigset_t old;

        extern int block_procsigmask(struct proc *p,  int bit);
        old = cfs_current()->uu_sigmask;
        block_procsigmask(p, ~sigs);

        return old;
}
#endif

#endif


