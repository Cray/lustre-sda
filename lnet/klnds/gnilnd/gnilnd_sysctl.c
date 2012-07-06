/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2012 Cray, Inc.
 *   Author: Nic Henke <nic@cray.com>
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
 */

/* this code liberated and modified from Lustre */

#define DEBUG_SUBSYSTEM S_LND

#include "gnilnd.h"

typedef struct kgn_sysctl_data 
{
        int                     ksd_pause_trigger;
        int                     ksd_quiesce_secs;
        int                     ksd_rdmaq_override;
} kgn_sysctl_data_t;

static kgn_sysctl_data_t        kgnilnd_sysctl;

#if defined(CONFIG_SYSCTL)

static cfs_sysctl_table_header_t *kgnilnd_table_header = NULL;
#ifndef HAVE_SYSCTL_UNNUMBERED

enum {
        GNILND_VERSION = 1,
        GNILND_THREAD_PAUSE,
        GNILND_HW_QUIESCE,
        GNILND_STACK_RESET,
        GNILND_RDMAQ_OVERRIDE,
};
#else
#define GNILND_VERSION             CTL_UNNUMBERED
#define GNILND_THREAD_PAUSE        CTL_UNNUMBERED
#define GNILND_HW_QUIESCE          CTL_UNNUMBERED
#define GNILND_STACK_RESET         CTL_UNNUMBERED
#define GNILND_RDMAQ_OVERRIDE      CTL_UNNUMBERED
#endif

static int LL_PROC_PROTO(proc_toggle_thread_pause)
{
        int  old_val = kgnilnd_sysctl.ksd_pause_trigger;
        int  rc = 0;
        ENTRY; 
        
        rc = ll_proc_dointvec(table, write, filp, buffer, lenp, ppos);
        if (!write) {
                /* read */
                RETURN(rc);
        }

        if (kgnilnd_data.kgn_init != GNILND_INIT_ALL) {
                rc = -EINVAL;
                RETURN(rc); 
        }

        if (old_val != kgnilnd_sysctl.ksd_pause_trigger) {
                down(&kgnilnd_data.kgn_quiesce_sem);
                CDEBUG(D_NET, "setting quiesce_trigger %d\n", old_val);
                kgnilnd_data.kgn_quiesce_trigger = kgnilnd_sysctl.ksd_pause_trigger;
                kgnilnd_quiesce_wait("admin sysctl");
                up(&kgnilnd_data.kgn_quiesce_sem);
        }

        RETURN(rc);
}

static int LL_PROC_PROTO(proc_hw_quiesce)
{
        int              rc = 0;
        kgn_device_t    *dev;
        ENTRY; 
        
        rc = ll_proc_dointvec(table, write, filp, buffer, lenp, ppos);
        if (!write) {
                /* read */
                RETURN(rc);
        }

        if (kgnilnd_data.kgn_init != GNILND_INIT_ALL) {
                rc = -EINVAL;
                RETURN(rc); 
        }

        
        /* only device 0 gets the handle, see kgnilnd_dev_init */
        dev = &kgnilnd_data.kgn_devices[0];

        LASSERTF(dev != NULL, "dev 0 is NULL\n");

        kgnilnd_quiesce_end_callback(dev->gnd_handle, 
                                     kgnilnd_sysctl.ksd_quiesce_secs * MSEC_PER_SEC);

        RETURN(rc);
}

int LL_PROC_PROTO(proc_trigger_stack_reset)
{
        int              rc = 0;
        int                i = 1;
       kgn_device_t    *dev;
        ENTRY;
        
        if (!write) {
                /* read */
                rc = ll_proc_dointvec(table, write, filp, buffer, lenp, ppos);
                RETURN(rc);
        }

        /* only device 0 gets the handle, see kgnilnd_dev_init */
        dev = &kgnilnd_data.kgn_devices[0];

        LASSERTF(dev != NULL, "dev 0 is NULL\n");

        kgnilnd_critical_error(dev->gnd_err_handle);

        /* Wait for the reset to complete.  This prevents any races in testing
         * where we'd immediately try to send traffic again */
       while (kgnilnd_data.kgn_needs_reset != 0) {
               i++;
               LCONSOLE((((i) & (-i)) == i) ? D_WARNING : D_NET,
                               "Waiting forstack reset request to clear\n");
               cfs_pause(cfs_time_seconds(1 * i));
       }

        RETURN(rc);
}

static int LL_PROC_PROTO(proc_toggle_rdmaq_override)
{
        int  old_val = kgnilnd_sysctl.ksd_rdmaq_override;
        int  rc = 0;
        ENTRY; 
        
        rc = ll_proc_dointvec(table, write, filp, buffer, lenp, ppos);
        if (!write) {
                /* read */
                RETURN(rc);
        }

        if (kgnilnd_data.kgn_init != GNILND_INIT_ALL) {
                rc = -EINVAL;
                RETURN(rc); 
        }

        if (old_val != kgnilnd_sysctl.ksd_rdmaq_override) {
                long    new_mb = kgnilnd_sysctl.ksd_rdmaq_override * (long)(1024*1024);
                LCONSOLE_INFO("changing RDMAQ override to %d mbytes/sec\n",
                              kgnilnd_sysctl.ksd_rdmaq_override);
                /* override proc is mbytes, but we calc in bytes */
                kgnilnd_data.kgn_rdmaq_override = new_mb;
                smp_wmb();
        }

        RETURN(rc);
}

static cfs_sysctl_table_t kgnilnd_table[] = {
        /*
         * NB No .strategy entries have been provided since sysctl(8) prefers
         * to go via /proc for portability.
         */
        {
                .ctl_name = GNILND_VERSION,
                .procname = "version",
                .data     = KGNILND_BUILD_REV,
                .maxlen   = sizeof(KGNILND_BUILD_REV),
                .mode     = 0444,
                .proc_handler = &proc_dostring
        },
        {
                .ctl_name = GNILND_THREAD_PAUSE,
                .procname = "thread_pause",
                .data     = &kgnilnd_sysctl.ksd_pause_trigger,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_toggle_thread_pause,
        },
        {
                .ctl_name = GNILND_HW_QUIESCE,
                .procname = "hw_quiesce",
                .data     = &kgnilnd_sysctl.ksd_quiesce_secs,
                .maxlen   = sizeof(__u32),
                .mode     = 0644,
                .proc_handler = &proc_hw_quiesce,
        },
        {
                .ctl_name = GNILND_STACK_RESET,
                .procname = "stack_reset",
                .data     = NULL,
                .maxlen   = sizeof(int),
                .mode     = 0600,
                .proc_handler = &proc_trigger_stack_reset,
        },
        {
                .ctl_name = GNILND_RDMAQ_OVERRIDE,
                .procname = "rdmaq_override",
                .data     = &kgnilnd_sysctl.ksd_rdmaq_override,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_toggle_rdmaq_override,
        },
        {0}
};

static cfs_sysctl_table_t kgnilnd_top_table[2] = {
        {
                .ctl_name = CTL_GNILND,
                .procname = "kgnilnd",
                .data     = NULL,
                .maxlen   = 0,
                .mode     = 0555,
                .child    = kgnilnd_table
        },
        {0}
};
         
void kgnilnd_insert_sysctl(void)
{
        if (kgnilnd_table_header == NULL)
                kgnilnd_table_header = cfs_register_sysctl_table(kgnilnd_top_table, 0);
}

void kgnilnd_remove_sysctl(void)
{
        if (kgnilnd_table_header != NULL)
                cfs_unregister_sysctl_table(kgnilnd_table_header);

        kgnilnd_table_header = NULL;
}

#else
void kgnilnd_insert_sysctl(void) {}
void kgnilnd_remove_sysctl(void) {}
#endif
