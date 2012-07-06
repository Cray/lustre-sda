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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Oracle Microsystems, Inc.
 */

#ifndef __KERNEL__
#include <liblustre.h>
#else
#include <libcfs/libcfs.h>
#endif

unsigned int cfs_fail_loc = 0;
unsigned int cfs_fail_val = 0;
cfs_waitq_t cfs_race_waitq;
int cfs_race_state;

EXPORT_SYMBOL(cfs_fail_loc);
EXPORT_SYMBOL(cfs_fail_val);
EXPORT_SYMBOL(cfs_race_waitq);
EXPORT_SYMBOL(cfs_race_state);

int cfs_fail_check(__u32 id)
{
        static int count = 0;
        if (likely((cfs_fail_loc & CFS_FAIL_MASK_LOC) !=
                   (id & CFS_FAIL_MASK_LOC)))
                return 0;

        if ((cfs_fail_loc & (CFS_FAILED | CFS_FAIL_ONCE)) ==
            (CFS_FAILED | CFS_FAIL_ONCE)) {
                count = 0; /* paranoia */
                return 0;
        }

        if (cfs_fail_loc & CFS_FAIL_RAND) {
                if (cfs_fail_val < 2)
                        return 0;
                if (cfs_rand() % cfs_fail_val > 0)
                        return 0;
        }

        if (cfs_fail_loc & CFS_FAIL_SKIP) {
                count++;
                if (count < cfs_fail_val)
                        return 0;
                count = 0;
        }

        /* Overridden by FAIL_ONCE */
        if (cfs_fail_loc & CFS_FAIL_SOME) {
                count++;
                if (count >= cfs_fail_val) {
                        count = 0;
                        /* Don't fail anymore */
                        cfs_fail_loc |= CFS_FAIL_ONCE;
                }
        }

        cfs_fail_loc |= CFS_FAILED;
        /* Handle old checks that OR in this */
        if (id & CFS_FAIL_ONCE)
                cfs_fail_loc |= CFS_FAIL_ONCE;

        return 1;
}
EXPORT_SYMBOL(cfs_fail_check);

#ifdef __KERNEL__
unsigned int cfs_print_fail_loc(void)
{
        CWARN("cfs_fail_loc = %x\n", cfs_fail_loc);
        return cfs_fail_loc;
}
EXPORT_SYMBOL(cfs_print_fail_loc);

void cfs_set_fail_loc(unsigned int fl)
{
        cfs_fail_loc = fl;
}
EXPORT_SYMBOL(cfs_set_fail_loc);
#endif
