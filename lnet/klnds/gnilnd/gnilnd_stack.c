/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2009 Cray, Inc.
 *   Author: Igor Gorodetsky <iogordet@cray.com>
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
 *
 */
#include "gnilnd.h"

/* Advance all timeouts by nap_time seconds. */
void
kgnilnd_bump_timeouts(__u32 nap_time, char *reason)
{
        int                     i;
        kgn_peer_t             *peer;
        kgn_conn_t             *conn;
        kgn_tx_t               *tx;
        kgn_device_t           *dev;
        kgn_dgram_t            *dgram;

        LCONSOLE_INFO("%s: bumping all timeouts by %ds\n", reason, nap_time);

        LASSERTF(GNILND_IS_QUIESCED, "gnilnd not quiesced %d != %d\n",
                 atomic_read(&kgnilnd_data.kgn_nquiesce),
                 atomic_read(&kgnilnd_data.kgn_nthreads));

        /* requiring that the threads are paused ensures a couple of things:
         * - combined code paths for stack reset and quiesce event as stack reset
         *   runs with the threads paused
         * - prevents traffic to the Gemini during a quiesce period
         * - reduces the locking requirements
        */

        for (i = 0; i < *kgnilnd_tunables.kgn_peer_hash_size; i++) {
                list_for_each_entry(peer, &kgnilnd_data.kgn_peers[i], gnp_list) {

                        /* we can reconnect again at any time */
                        peer->gnp_reconnect_time = jiffies;
                        /* reset now that network is healthy */
                        peer->gnp_reconnect_interval = 0;
                        /* tell LNet dude is still alive */
                        kgnilnd_peer_alive(peer);

                        list_for_each_entry(tx, &peer->gnp_tx_queue, tx_list) {
                                tx->tx_qtime = jiffies;
                        }

                        list_for_each_entry(conn, &peer->gnp_conns, gnc_list) {
                                unsigned long           timeout;

                                timeout = cfs_time_seconds(conn->gnc_timeout);

                                /* bump last_rx/last_rx_cq on all conns - including
                                 * closed ones, this will have the effect of
                                 * bumping the purgatory timers for those */
                                conn->gnc_last_rx = conn->gnc_last_rx_cq = jiffies;

                                /* we don't timeout based on old gnc_last_tx, so
                                 * we'll back it up and schedule the conn to trigger
                                 * a NOOP */
                                conn->gnc_last_tx = jiffies - timeout;
                                kgnilnd_schedule_conn(conn);
                        }
                }
        }

        for (i = 0; i < kgnilnd_data.kgn_ndevs; i++) {
                dev = &kgnilnd_data.kgn_devices[i];
                for (i = 0; i < (*kgnilnd_tunables.kgn_peer_hash_size - 1); i++) {
                        list_for_each_entry(dgram, &dev->gnd_dgrams[i], gndg_list) {
                                dgram->gndg_post_time = jiffies;
                        }
                }
        }
}

/* Quiesce or wake up the stack.  The caller must hold the kgn_quiesce_sem semaphore
 * on entry, which holds off any pending stack shutdown.   */
void
kgnilnd_quiesce_wait(char *reason)
{
        int             i;
        
        if (kgnilnd_data.kgn_quiesce_trigger) {
                unsigned long   quiesce_deadline, quiesce_to;
                /* FREEZE TAG!!!! */

                /* morning sunshine */
                spin_lock(&kgnilnd_data.kgn_reaper_lock);
                wake_up_all(&kgnilnd_data.kgn_reaper_waitq);
                spin_unlock(&kgnilnd_data.kgn_reaper_lock);

                for (i = 0; i < kgnilnd_data.kgn_ndevs; i++) {
                        kgn_device_t *dev = &kgnilnd_data.kgn_devices[i];

                        wake_up_all(&dev->gnd_waitq);
                        wake_up_all(&dev->gnd_dgram_waitq);
                        wake_up_all(&dev->gnd_dgping_waitq);
                }

                /* we'll wait for 10x the timeout for the threads to pause */
                quiesce_to = cfs_time_seconds(*kgnilnd_tunables.kgn_timeout * 10);
                quiesce_deadline = (long) jiffies + quiesce_to;

                /* wait for everyone to check-in as quiesced */
                i = 1;
                while (!GNILND_IS_QUIESCED) {
                        i++;
                        LCONSOLE((((i) & (-i)) == i) ? D_WARNING : D_NET,
                                 "%s: Waiting for %d threads to pause\n",
                                 reason,
                                 atomic_read(&kgnilnd_data.kgn_nthreads) - 
                                 atomic_read(&kgnilnd_data.kgn_nquiesce));
                        CFS_RACE(CFS_FAIL_GNI_QUIESCE_RACE);
                        cfs_pause(cfs_time_seconds(1 * i));

                        LASSERTF(quiesce_deadline > jiffies,
                                 "couldn't quiesce threads in %lu seconds, falling over now\n",
                                 cfs_duration_sec(quiesce_to));
                }

                LCONSOLE_WARN("%s: All threads paused!\n", reason);
                /* XXX Nic: Is there a set of counters we can grab here to 
                 * ensure that there is no traffic until quiesce is over ?*/
        } else {
                /* GO! GO! GO! */
                for (i = 0; i < kgnilnd_data.kgn_ndevs; i++) {
                        kgn_device_t *dev = &kgnilnd_data.kgn_devices[i];
                        kgnilnd_schedule_dgram(dev);
                }

                /* wait for everyone to check-in as running - they will be spinning
                 * and looking, so no need to poke any waitq */
                i = 1;
                while (atomic_read(&kgnilnd_data.kgn_nquiesce) > 0) {
                        i++;
                        LCONSOLE((((i) & (-i)) == i) ? D_WARNING : D_NET,
                                 "%s: Waiting for %d threads to wake up\n",
                                  reason, 
                                  atomic_read(&kgnilnd_data.kgn_nquiesce));
                        cfs_pause(cfs_time_seconds(1 * i));
                }

                LCONSOLE_WARN("%s: All threads awake!\n", reason);
        }
}

/* Reset the stack.  */
void
kgnilnd_reset_stack(void)
{
        int              i, rc = 0;
        gni_return_t     grc;
        kgn_net_t       *net;
        kgn_peer_t      *peer, *peerN;
        CFS_LIST_HEAD   (souls);
        char            *reason = "critical hardware error";
        __u32            seconds;
        unsigned long    start, end;
        ENTRY;

        if (kgnilnd_data.kgn_init != GNILND_INIT_ALL) {
                CERROR("can't reset the stack, gnilnd is not initialized\n");
                RETURN_EXIT;
        }

        /* First make sure we are not already quiesced - we panic if so,
         * as that could leave software in a bad state */
        LASSERTF(kgnilnd_data.kgn_quiesce_trigger == GNILND_QUIESCE_IDLE,
                "can't reset the stack, already doing so: trigger %d\n",
                 kgnilnd_data.kgn_quiesce_trigger);

        set_mb(kgnilnd_data.kgn_quiesce_trigger, GNILND_QUIESCE_RESET);

        /* wake up the dgram waitq thread - but after trigger set to make sure it
         * goes into quiesce */
        CFS_RACE(CFS_FAIL_GNI_WC_DGRAM_FREE);
        /* same for scheduler that is dropping state transitiosn */
        CFS_RACE(CFS_FAIL_GNI_DROP_CLOSING);
        CFS_RACE(CFS_FAIL_GNI_DROP_DESTROY_EP);

        kgnilnd_quiesce_wait(reason);

        start = jiffies;
        
        kgnilnd_data.kgn_in_reset = 1;
        kgnilnd_data.kgn_nresets++;
        LCONSOLE_WARN("%s: resetting all resources (count %d)\n",
                      reason, kgnilnd_data.kgn_nresets);

        list_for_each_entry(net, &kgnilnd_data.kgn_nets, gnn_list) {
                rc = kgnilnd_cancel_all_dgrams(net);
                LASSERTF(rc == 0, "couldn't cleanup datagrams: %d\n",rc);
        }

        /* error -ENOTRECOVERABLE is stack reset */
        kgnilnd_del_conn_or_peer(NULL, LNET_NID_ANY, GNILND_DEL_CONN, -ENOTRECOVERABLE);  

        list_for_each_entry(net, &kgnilnd_data.kgn_nets, gnn_list) {
                kgnilnd_wait_for_canceled_dgrams(net);

                /* we now have no datagrams left on the net, so tear down 
                 * the cdm we use for datagrams - this ensures any dangling
                 * matches to the wildcards are nuked too */
                grc = kgnilnd_cdm_destroy(net->gnn_domain);
                LASSERTF(grc == GNI_RC_SUCCESS, 
                        "bad rc on net %d from gni_cdm_destroy: %d\n", 
                        net->gnn_netnum, grc);
                net->gnn_domain = NULL;
        }

        /* manually do some conn processing ala kgnilnd_process_conns */
        for (i = 0; i < kgnilnd_data.kgn_ndevs; i++) {
                kgn_device_t    *dev = &kgnilnd_data.kgn_devices[i];
                kgn_conn_t      *conn;
                int              conn_sched;

                /* go find all the closed conns that need to be nuked - the
                 * scheduler thread isn't running to do this for us */

                CDEBUG(D_NET, "will try to clear up %d ready_conns\n",
                        kgnilnd_count_list(&dev->gnd_ready_conns));

                /* use while/list_first_entry loop to ensure we can handle any
                 * DESTROY_EP conns added from kgnilnd_complete_closed_conn */
                while (!list_empty(&dev->gnd_ready_conns)) {
                        conn = list_first_entry(&dev->gnd_ready_conns, 
                                                kgn_conn_t, gnc_schedlist);

                        list_del_init(&conn->gnc_schedlist);
                        conn_sched = xchg(&conn->gnc_scheduled, GNILND_CONN_IDLE);
                        LASSERTF(conn_sched != GNILND_CONN_IDLE,
                                "conn %p on ready list but not scheduled: %d\n",
                                conn, conn_sched);

                        if (conn->gnc_state == GNILND_CONN_CLOSING) {
                                /* bump to CLOSED to fake out send of CLOSE */
                                conn->gnc_state = GNILND_CONN_CLOSED;
                                conn->gnc_close_sent = 1;
                        }

                        if (conn->gnc_state == GNILND_CONN_DESTROY_EP) {
                                kgnilnd_destroy_conn_ep(conn);
                        } else {
                                kgnilnd_complete_closed_conn(conn);
                        }
        
                        /* there really shouldn't be any other states here -
                         * they would have been cleared out in the del_peer_or_conn or the dgram
                         * aborts above.
                         * there is an LASSERTF in kgnilnd_complete_closed_conn that will take 
                         * care of catching anything else for us */

                        kgnilnd_conn_decref(conn);
                }
        }

        /* don't let the little weasily purgatory conns hide from us */
        for (i = 0; i < *kgnilnd_tunables.kgn_peer_hash_size; i++) {
                list_for_each_entry_safe(peer, peerN, &kgnilnd_data.kgn_peers[i], gnp_list) {
                        kgnilnd_detach_purgatory_locked(peer, &souls);
                }
        }

        CDEBUG(D_NET, "about to release %d purgatory entries\n",
                kgnilnd_count_list(&souls));

        kgnilnd_release_purgatory_list(&souls);

        /* validate we are now clean */
        for (i = 0; i < kgnilnd_data.kgn_ndevs; i++) {
                kgn_device_t    *dev = &kgnilnd_data.kgn_devices[i];

                LASSERTF(atomic_read(&dev->gnd_nfmablk) == 0,
                        "reset failed: fma blocks still live %d\n",
                        atomic_read(&dev->gnd_nfmablk));

                LASSERTF(atomic_read(&dev->gnd_neps) == 0,
                        "reset failed: EP handles still live %d\n",
                        atomic_read(&dev->gnd_neps));
        }
       
        LASSERTF(atomic_read(&kgnilnd_data.kgn_nconns) == 0,
                "reset failed: conns left %d\n", 
                atomic_read(&kgnilnd_data.kgn_nconns));

        /* fine to have peers left - they are waiting for new conns 
         * but should not be holding any open HW resources */

        /* like the last part of kgnilnd_base_shutdown() */

        CFS_RACE(CFS_FAIL_GNI_SR_DOWN_RACE);

        for (i = 0; i < kgnilnd_data.kgn_ndevs; i++) {
                kgnilnd_dev_fini(&kgnilnd_data.kgn_devices[i]);
        }

        /* no need to free and recreate the TX descriptors 
         * we nuked all the ones that could be using HW resources in
         * kgnilnd_close_matching_conns and asserted it worked in
         * kgnilnd_dev_fini */

        /* At this point, all HW is torn down, start to reset */
        
        /* only reset our known devs */
        for (i = 0; i < kgnilnd_data.kgn_ndevs; i++) {
                rc = kgnilnd_dev_init(&kgnilnd_data.kgn_devices[i]);
                LASSERTF(rc == 0, "dev_init failed for dev %d\n", i);
        }

        list_for_each_entry(net, &kgnilnd_data.kgn_nets, gnn_list) {
                __u32           dummy_host_id;
                /* make sure we get a new fresh CDM to use */

                grc = kgnilnd_cdm_create(net->gnn_inst_id, 
                                         *kgnilnd_tunables.kgn_ptag,
                                         GNILND_COOKIE, 0, &net->gnn_domain);
                LASSERTF(grc == GNI_RC_SUCCESS, 
                         "gni_cdm_create for CDM %d returned %d for net %d\n",
                         net->gnn_inst_id, net->gnn_netnum, grc);

                /* this device already has a host_id, so just throw this one away
                 * -- it better be the same as the device! */
                grc = kgnilnd_cdm_attach(net->gnn_domain, net->gnn_dev->gnd_id, 
                                         &dummy_host_id, &net->gnn_handle);
                LASSERTF(grc == GNI_RC_SUCCESS, 
                         "gni_cdm_attach for CDM %d returned %d for net %d\n",
                         net->gnn_inst_id, net->gnn_netnum, grc);

                rc = kgnilnd_setup_wildcard_dgram(net);
                LASSERTF(rc == 0, "couldn't setup datagrams on net %d: %d\n",
                         net->gnn_netnum, rc);
        }

        /* Now the fun restarts... - release the hounds! */

        end = jiffies;
        seconds = cfs_duration_sec((long)end - start);
        kgnilnd_bump_timeouts(seconds, reason);

        kgnilnd_data.kgn_in_reset = 0;
        set_mb(kgnilnd_data.kgn_quiesce_trigger, GNILND_QUIESCE_IDLE);
        kgnilnd_quiesce_wait(reason);
        LCONSOLE_WARN("%s reset of all hardware resources\n",
                rc ? "failed" : "successful");

        RETURN_EXIT;
}

/* A thread that handles quiece and reset hardware events.
 * We do the same thing regardless of which device reported the event. */
int
kgnilnd_ruhroh_thread (void *arg)
{
        int                i = 1;
        DEFINE_WAIT(wait);

        cfs_daemonize("kgnilnd_rr");
        cfs_block_allsigs();
        set_user_nice(current, *kgnilnd_tunables.kgn_nice);
        kgnilnd_data.kgn_ruhroh_running = 1;

        while (1) {

                /* Block until there's a request..  A reset request could come in
                 * while we're handling a quiesce one, or vice versa.
                 * Keep processing requests until there are none.*/
                prepare_to_wait(&kgnilnd_data.kgn_ruhroh_waitq, &wait, TASK_INTERRUPTIBLE);
                while (!(kgnilnd_data.kgn_ruhroh_shutdown ||
                		kgnilnd_data.kgn_needs_reset || kgnilnd_data.kgn_needs_pause))
                        schedule();
                finish_wait(&kgnilnd_data.kgn_ruhroh_waitq, &wait);

               /* Exit if the driver is shutting down. */
                if (kgnilnd_data.kgn_ruhroh_shutdown)
                        break;

                /* Serialize with driver startup and shutdown. */
                down(&kgnilnd_data.kgn_quiesce_sem);

               CDEBUG(D_NET, "trigger %d reset %d to_bump %d pause %d\n",
                        kgnilnd_data.kgn_quiesce_trigger,
                        kgnilnd_data.kgn_needs_reset,
                        kgnilnd_data.kgn_bump_info_rdy,
                        kgnilnd_data.kgn_needs_pause);

                /* Do we need to do a pause/quiesce? */
                if (kgnilnd_data.kgn_needs_pause) {

			/* Pause all other kgnilnd threads. */
			set_mb(kgnilnd_data.kgn_quiesce_trigger, GNILND_QUIESCE_HW_QUIESCE);
			kgnilnd_quiesce_wait("hardware quiesce flag");

			/* If the hardware quiesce flag is set, wait for it to clear.
			 * This should happen relatively quickly, so we wait for it.
			 * This will hold up the eventd thread, but on everything but
			 * the simulator, this is ok-- there is one thread per core.
			 *
			 * Handle (possibly multiple) quiesce events while we wait. The
			 * memory barrier ensures that the core doesn't start fetching
			 * kgn_bump_info_rdy before it fetches kgn_needs_pause, and
			 * matches the second mb in kgnilnd_quiesce_end_callback(). */
			smp_rmb();
                        while (kgnilnd_hw_in_quiesce() || kgnilnd_data.kgn_bump_info_rdy) {

                                i++;
                                LCONSOLE((((i) & (-i)) == i) ? D_WARNING : D_NET,
                                                "Waiting for hardware quiesce flag to clear\n");
                                cfs_pause(cfs_time_seconds(1 * i));

                                /* If we got a quiesce event with bump info, DO THE BUMP!. */
                                if (kgnilnd_data.kgn_bump_info_rdy) {
                                        /* reset console rate limiting for each event */
                                        i = 1;

                                        /* Make sure the core doesn't start fetching
                                         * kgni_quiesce_seconds until after it sees
                                         * kgn_bump_info_rdy set.  This is the match to the
                                         * first mb in kgnilnd_quiesce_end_callback(). */
                                        smp_rmb();
                                        (void) kgnilnd_bump_timeouts(kgnilnd_data.kgn_quiesce_secs,
                                                               "hardware quiesce callback");
                                        set_mb(kgnilnd_data.kgn_quiesce_secs, 0);
                                        set_mb(kgnilnd_data.kgn_bump_info_rdy, 0);
                                }
                      }

                        /* Reset the kgn_needs_pause flag before coming out of
                         * the pause.  This ordering avoids a race with the
                         * setting of this flag in kgnilnd_pause_threads().  */
                        set_mb(kgnilnd_data.kgn_needs_pause, 0);

                        /* ok, let the kids back into the pool */
                        set_mb(kgnilnd_data.kgn_quiesce_trigger, GNILND_QUIESCE_IDLE);
                        kgnilnd_quiesce_wait("hardware quiesce");
                }

                /* Do a stack reset if needed. */
                if (kgnilnd_data.kgn_needs_reset) {
                        kgnilnd_reset_stack();
                        set_mb(kgnilnd_data.kgn_needs_reset, 0);
                }

                up(&kgnilnd_data.kgn_quiesce_sem);
        }

        kgnilnd_data.kgn_ruhroh_running = 0;
        return 0;
}

/* Set pause request flag.  Any functions that
 * call this one are responsible for ensuring that
 * variables they set up are visible on other cores before
 * this flag setting.  This executes in interrupt or kernel
 * thread context.  */
void
kgnilnd_pause_threads(void)
{
        /* only device 0 gets the handle, see kgnilnd_dev_init */
        kgn_device_t  *dev = &kgnilnd_data.kgn_devices[0];
        LASSERTF(dev != NULL, "dev 0 is NULL\n");

        /* If we're currently in a pause triggered by the pause flag,
         * there's no need to set it again.  We clear the kgn_needs_pause
         * flag before we reset kgn_quiesce_trigger to avoid a race.  The
         * read memory barrier matches the setmb() on the trigger in
         * kgnilnd_ruhroh_task().					*/
        smp_rmb();
        if (!(kgnilnd_data.kgn_quiesce_trigger == GNILND_QUIESCE_HW_QUIESCE &&
                        GNILND_IS_QUIESCED)) {
                 CDEBUG(D_NET, "requesting thread pause\n");

                kgnilnd_data.kgn_needs_pause = 1;

                wake_up(&kgnilnd_data.kgn_ruhroh_waitq);
        }
        else {
            CDEBUG(D_NET, "thread pause already underway\n");
        }
}

/* Return non-zero if the GNI hardware quiesce flag is set */
int
kgnilnd_hw_in_quiesce(void)
{
        /* only device 0 gets the handle, see kgnilnd_dev_init */
        kgn_device_t      *dev0 = &kgnilnd_data.kgn_devices[0];

        LASSERTF(dev0 != NULL, "dev 0 is NULL\n");

        smp_rmb();
        return kgnilnd_get_quiesce_status(dev0->gnd_handle) != 0;
}


/* If the GNI hardware quiesce flag is set, initiate our pause and
 * return non-zero.  Also return non-zero if the stack is shutting down. */
int
kgnilnd_check_hw_quiesce(void)
{
        if (likely(!kgnilnd_hw_in_quiesce()))
                return 0;

        if (!kgnilnd_data.kgn_ruhroh_shutdown) {
                CDEBUG(D_NET, "initiating thread pause\n");
                kgnilnd_pause_threads();
        }
        else {
                CDEBUG(D_NET, "thread pause bypassed because of shutdown\n");
        }

        return 1;
}

/* Callback from kngi with the quiesce duration.  This executes
 * in interrupt context.                                        */
void
kgnilnd_quiesce_end_callback(gni_nic_handle_t nic_handle, uint64_t msecs)
{
        /* only device 0 gets the handle, see kgnilnd_dev_init */
        kgn_device_t  *dev = &kgnilnd_data.kgn_devices[0];
        LASSERTF(dev != NULL, "dev 0 is NULL\n");

        if (!kgnilnd_data.kgn_ruhroh_shutdown) {

                CDEBUG(D_NET, "requesting timeout bump by "LPD64" msecs\n", msecs);

                /* Save the bump interval and request the bump.
                 * The memory barrier ensures that the interval is in place before
                 * the bump flag can be seen (in case a core is already running the
                 * ruhroh task), and that the bump request flag in place before
                 * the pause request can be seen (to ensure a core doesn't miss the bump
                 * request flag).       */
                /* If another callback occurred before the ruhroh task
                 * finished processing the first bump request, we'd over-write its info.
                 * Nic says that callbacks occur so slowly that this isn't an issue.    */
                set_mb(kgnilnd_data.kgn_quiesce_secs, msecs / MSEC_PER_SEC);
                set_mb(kgnilnd_data.kgn_bump_info_rdy, 1);
                kgnilnd_pause_threads();
        }
        else {
                CDEBUG(D_NET, "timeout bump bypassed because of shutdown\n");
        }
}

void
kgnilnd_critical_error(struct gni_err *err_handle)
{
        /* only device 0 gets the handle, see kgnilnd_dev_init */
        kgn_device_t  *dev = &kgnilnd_data.kgn_devices[0];
        LASSERTF(dev != NULL, "dev 0 is NULL\n");

        if (!kgnilnd_data.kgn_ruhroh_shutdown){
                CDEBUG(D_NET, "requesting stack reset\n");
                kgnilnd_data.kgn_needs_reset = 1;
                wake_up(&kgnilnd_data.kgn_ruhroh_waitq);
        }
        else {
                CDEBUG(D_NET, "stack reset bypassed because of shutdown\n");
        }
}
