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
 *
 * Copyright (c) 2011, Whamcloud, Inc.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#define DEBUG_SUBSYSTEM S_LNET
#include <lnet/lib-lnet.h>

#if defined(__KERNEL__) || defined(HAVE_LIBPTHREAD)

static int   accept_port    = 988;
static int   accept_backlog = 127;
static int   accept_timeout = 5;

struct {
        int                   pta_shutdown;
        cfs_socket_t         *pta_sock;
#ifdef __KERNEL__
        cfs_completion_t      pta_signal;
#else
        cfs_mt_completion_t   pta_signal;
#endif
} lnet_acceptor_state;

int
lnet_acceptor_port(void)
{
        return accept_port;
}

static inline int
lnet_accept_magic(__u32 magic, __u32 constant)
{
        return (magic == constant ||
                magic == __swab32(constant));
}

#ifdef __KERNEL__

#define cfs_mt_init_completion(c)     cfs_init_completion(c)
#define cfs_mt_wait_for_completion(c) cfs_wait_for_completion(c)
#define cfs_mt_complete(c)            cfs_complete(c)
#define cfs_mt_fini_completion(c)     cfs_fini_completion(c)

EXPORT_SYMBOL(lnet_acceptor_port);

static char *accept = "secure";

CFS_MODULE_PARM(accept, "s", charp, 0444,
                "Accept connections (secure|all|none)");
CFS_MODULE_PARM(accept_port, "i", int, 0444,
                "Acceptor's port (same on all nodes)");
CFS_MODULE_PARM(accept_backlog, "i", int, 0444,
                "Acceptor's listen backlog");
CFS_MODULE_PARM(accept_timeout, "i", int, 0644,
                "Acceptor's timeout (seconds)");

static char *accept_type = NULL;

int
lnet_acceptor_get_tunables(void)
{
        /* Userland acceptor uses 'accept_type' instead of 'accept', due to
         * conflict with 'accept(2)', but kernel acceptor still uses 'accept'
         * for compatibility. Hence the trick. */
        accept_type = accept;
        return 0;
}

int
lnet_acceptor_timeout(void)
{
        return accept_timeout;
}
EXPORT_SYMBOL(lnet_acceptor_timeout);

void
lnet_connect_console_error (int rc, lnet_nid_t peer_nid,
                           __u32 peer_ip, int peer_port)
{
        switch (rc) {
        /* "normal" errors */
        case -ECONNREFUSED:
                CNETERR("Connection to %s at host %u.%u.%u.%u on port %d was "
                        "refused: check that Lustre is running on that node.\n",
                        libcfs_nid2str(peer_nid),
                        HIPQUAD(peer_ip), peer_port);
                break;
        case -EHOSTUNREACH:
        case -ENETUNREACH:
                CNETERR("Connection to %s at host %u.%u.%u.%u "
                        "was unreachable: the network or that node may "
                        "be down, or Lustre may be misconfigured.\n",
                        libcfs_nid2str(peer_nid), HIPQUAD(peer_ip));
                break;
        case -ETIMEDOUT:
                CNETERR("Connection to %s at host %u.%u.%u.%u on "
                        "port %d took too long: that node may be hung "
                        "or experiencing high load.\n",
                        libcfs_nid2str(peer_nid),
                        HIPQUAD(peer_ip), peer_port);
                break;
        case -ECONNRESET:
                LCONSOLE_ERROR_MSG(0x11b, "Connection to %s at host %u.%u.%u.%u"
                                   " on port %d was reset: "
                                   "is it running a compatible version of "
                                   "Lustre and is %s one of its NIDs?\n",
                                   libcfs_nid2str(peer_nid),
                                   HIPQUAD(peer_ip), peer_port,
                                   libcfs_nid2str(peer_nid));
                break;
        case -EPROTO:
                LCONSOLE_ERROR_MSG(0x11c, "Protocol error connecting to %s at "
                                   "host %u.%u.%u.%u on port %d: is it running "
                                   "a compatible version of Lustre?\n",
                                   libcfs_nid2str(peer_nid),
                                   HIPQUAD(peer_ip), peer_port);
                break;
        case -EADDRINUSE:
                LCONSOLE_ERROR_MSG(0x11d, "No privileged ports available to "
                                   "connect to %s at host %u.%u.%u.%u on port "
                                   "%d\n", libcfs_nid2str(peer_nid),
                                   HIPQUAD(peer_ip), peer_port);
                break;
        default:
                LCONSOLE_ERROR_MSG(0x11e, "Unexpected error %d connecting to %s"
                                   " at host %u.%u.%u.%u on port %d\n", rc,
                                   libcfs_nid2str(peer_nid),
                                   HIPQUAD(peer_ip), peer_port);
                break;
        }
}
EXPORT_SYMBOL(lnet_connect_console_error);

int
lnet_connect(cfs_socket_t **sockp, lnet_nid_t peer_nid,
            __u32 local_ip, __u32 peer_ip, int peer_port)
{
        lnet_acceptor_connreq_t cr;
        cfs_socket_t           *sock;
        int                     rc;
        int                     port;
        int                     fatal;

        CLASSERT (sizeof(cr) <= 16);            /* not too big to be on the stack */

        for (port = LNET_ACCEPTOR_MAX_RESERVED_PORT;
             port >= LNET_ACCEPTOR_MIN_RESERVED_PORT;
             --port) {
                /* Iterate through reserved ports. */

                rc = libcfs_sock_connect(&sock, &fatal,
                                         local_ip, port,
                                         peer_ip, peer_port);
                if (rc != 0) {
                        if (fatal)
                                goto failed;
                        continue;
                }

                CLASSERT (LNET_PROTO_ACCEPTOR_VERSION == 1);

                cr.acr_magic   = LNET_PROTO_ACCEPTOR_MAGIC;
                cr.acr_version = LNET_PROTO_ACCEPTOR_VERSION;
                cr.acr_nid     = peer_nid;

                if (the_lnet.ln_testprotocompat != 0) {
                        /* single-shot proto check */
                        LNET_LOCK();
                        if ((the_lnet.ln_testprotocompat & 4) != 0) {
                                cr.acr_version++;
                                the_lnet.ln_testprotocompat &= ~4;
                        }
                        if ((the_lnet.ln_testprotocompat & 8) != 0) {
                                cr.acr_magic = LNET_PROTO_MAGIC;
                                the_lnet.ln_testprotocompat &= ~8;
                        }
                        LNET_UNLOCK();
                }

                rc = libcfs_sock_write(sock, &cr, sizeof(cr),
                                       accept_timeout);
                if (rc != 0)
                        goto failed_sock;

                *sockp = sock;
                return 0;
        }

        rc = -EADDRINUSE;
        goto failed;

 failed_sock:
        libcfs_sock_release(sock);
 failed:
        lnet_connect_console_error(rc, peer_nid, peer_ip, peer_port);
        return rc;
}
EXPORT_SYMBOL(lnet_connect);

#else /* below is multi-threaded user-space code */

static char *accept_type = "secure";

int
lnet_acceptor_get_tunables()
{
        int   rc;
        char *env = getenv("LNET_ACCEPT");

        if (env != NULL)
                accept_type = env;

        rc = lnet_parse_int_tunable(&accept_port, "LNET_ACCEPT_PORT");

        if (rc != 0)
                return rc;

        rc = lnet_parse_int_tunable(&accept_backlog, "LNET_ACCEPT_BACKLOG");

        if (rc != 0)
                return rc;

        rc = lnet_parse_int_tunable(&accept_timeout, "LNET_ACCEPT_TIMEOUT");

        if (rc != 0)
                return rc;

        CDEBUG(D_NET, "accept_type     = %s\n", accept_type);
        CDEBUG(D_NET, "accept_port     = %d\n", accept_port);
        CDEBUG(D_NET, "accept_backlog  = %d\n", accept_backlog);
        CDEBUG(D_NET, "accept_timeout  = %d\n", accept_timeout);
        return 0;
}

#endif /* __KERNEL__ */

/* Below is the code common for both kernel and MT user-space */

int
lnet_accept(cfs_socket_t *sock, __u32 magic)
{
        lnet_acceptor_connreq_t cr;
        __u32                   peer_ip;
        int                     peer_port;
        int                     rc;
        int                     flip;
        lnet_ni_t              *ni;
        char                   *str;

        LASSERT (sizeof(cr) <= 16);             /* not too big for the stack */

        rc = libcfs_sock_getaddr(sock, 1, &peer_ip, &peer_port);
        LASSERT (rc == 0);                      /* we succeeded before */

        if (!lnet_accept_magic(magic, LNET_PROTO_ACCEPTOR_MAGIC)) {

                if (lnet_accept_magic(magic, LNET_PROTO_MAGIC)) {
                        /* future version compatibility!
                         * When LNET unifies protocols over all LNDs, the first
                         * thing sent will be a version query.  I send back
                         * LNET_PROTO_ACCEPTOR_MAGIC to tell her I'm "old" */

                        memset (&cr, 0, sizeof(cr));
                        cr.acr_magic = LNET_PROTO_ACCEPTOR_MAGIC;
                        cr.acr_version = LNET_PROTO_ACCEPTOR_VERSION;
                        rc = libcfs_sock_write(sock, &cr, sizeof(cr),
                                               accept_timeout);

                        if (rc != 0)
                                CERROR("Error sending magic+version in response"
                                       "to LNET magic from %u.%u.%u.%u: %d\n",
                                       HIPQUAD(peer_ip), rc);
                        return -EPROTO;
                }

                if (magic == le32_to_cpu(LNET_PROTO_TCP_MAGIC))
                        str = "'old' socknal/tcpnal";
                else if (lnet_accept_magic(magic, LNET_PROTO_RA_MAGIC))
                        str = "'old' ranal";
                else
                        str = "unrecognised";

                LCONSOLE_ERROR_MSG(0x11f, "Refusing connection from %u.%u.%u.%u"
                                   " magic %08x: %s acceptor protocol\n",
                                   HIPQUAD(peer_ip), magic, str);
                return -EPROTO;
        }

        flip = (magic != LNET_PROTO_ACCEPTOR_MAGIC);

        rc = libcfs_sock_read(sock, &cr.acr_version,
                              sizeof(cr.acr_version),
                              accept_timeout);
        if (rc != 0) {
                CERROR("Error %d reading connection request version from "
                       "%u.%u.%u.%u\n", rc, HIPQUAD(peer_ip));
                return -EIO;
        }

        if (flip)
                __swab32s(&cr.acr_version);

        if (cr.acr_version != LNET_PROTO_ACCEPTOR_VERSION) {
                /* future version compatibility!
                 * An acceptor-specific protocol rev will first send a version
                 * query.  I send back my current version to tell her I'm
                 * "old". */
                int peer_version = cr.acr_version;

                memset (&cr, 0, sizeof(cr));
                cr.acr_magic = LNET_PROTO_ACCEPTOR_MAGIC;
                cr.acr_version = LNET_PROTO_ACCEPTOR_VERSION;

                rc = libcfs_sock_write(sock, &cr, sizeof(cr),
                                       accept_timeout);

                if (rc != 0)
                        CERROR("Error sending magic+version in response"
                               "to version %d from %u.%u.%u.%u: %d\n",
                               peer_version, HIPQUAD(peer_ip), rc);
                return -EPROTO;
        }

        rc = libcfs_sock_read(sock, &cr.acr_nid,
                              sizeof(cr) -
                              offsetof(lnet_acceptor_connreq_t, acr_nid),
                              accept_timeout);
        if (rc != 0) {
                CERROR("Error %d reading connection request from "
                       "%u.%u.%u.%u\n", rc, HIPQUAD(peer_ip));
                return -EIO;
        }

        if (flip)
                __swab64s(&cr.acr_nid);

        ni = lnet_net2ni(LNET_NIDNET(cr.acr_nid));
        if (ni == NULL ||               /* no matching net */
            ni->ni_nid != cr.acr_nid) { /* right NET, wrong NID! */
                if (ni != NULL)
                        lnet_ni_decref(ni);
                LCONSOLE_ERROR_MSG(0x120, "Refusing connection from %u.%u.%u.%u"
                                   " for %s: No matching NI\n",
                                   HIPQUAD(peer_ip), libcfs_nid2str(cr.acr_nid));
                return -EPERM;
        }

        if (ni->ni_lnd->lnd_accept == NULL) {
                /* This catches a request for the loopback LND */
                lnet_ni_decref(ni);
                LCONSOLE_ERROR_MSG(0x121, "Refusing connection from %u.%u.%u.%u"
                                  " for %s: NI doesn not accept IP connections\n",
                                  HIPQUAD(peer_ip), libcfs_nid2str(cr.acr_nid));
                return -EPERM;
        }

        CDEBUG(D_NET, "Accept %s from %u.%u.%u.%u\n",
               libcfs_nid2str(cr.acr_nid), HIPQUAD(peer_ip));

        rc = ni->ni_lnd->lnd_accept(ni, sock);

        lnet_ni_decref(ni);
        return rc;
}

int
lnet_acceptor(void *arg)
{
        char           name[16];
        cfs_socket_t  *newsock;
        int            rc;
        __u32          magic;
        __u32          peer_ip;
        int            peer_port;
        int            secure = (int)((long_ptr_t)arg);

        LASSERT (lnet_acceptor_state.pta_sock == NULL);

        snprintf(name, sizeof(name), "acceptor_%03d", accept_port);
        cfs_daemonize(name);
        cfs_block_allsigs();

        rc = libcfs_sock_listen(&lnet_acceptor_state.pta_sock,
                                0, accept_port, accept_backlog);
        if (rc != 0) {
                if (rc == -EADDRINUSE)
                        LCONSOLE_ERROR_MSG(0x122, "Can't start acceptor on port"
                                           " %d: port already in use\n",
                                           accept_port);
                else
                        LCONSOLE_ERROR_MSG(0x123, "Can't start acceptor on port "
                                           "%d: unexpected error %d\n",
                                           accept_port, rc);

                lnet_acceptor_state.pta_sock = NULL;
        } else {
                LCONSOLE(0, "Accept %s, port %d\n", accept_type, accept_port);
        }

        /* set init status and unblock parent */
        lnet_acceptor_state.pta_shutdown = rc;
        cfs_mt_complete(&lnet_acceptor_state.pta_signal);

        if (rc != 0)
                return rc;

        while (!lnet_acceptor_state.pta_shutdown) {

                rc = libcfs_sock_accept(&newsock, lnet_acceptor_state.pta_sock);
                if (rc != 0) {
                        if (rc != -EAGAIN) {
                                CWARN("Accept error %d: pausing...\n", rc);
                                cfs_pause(cfs_time_seconds(1));
                        }
                        continue;
                }

                /* maybe we're waken up with libcfs_sock_abort_accept() */
                if (lnet_acceptor_state.pta_shutdown) {
                        libcfs_sock_release(newsock);
                        break;
                }

                rc = libcfs_sock_getaddr(newsock, 1, &peer_ip, &peer_port);
                if (rc != 0) {
                        CERROR("Can't determine new connection's address\n");
                        goto failed;
                }

                if (secure && peer_port > LNET_ACCEPTOR_MAX_RESERVED_PORT) {
                        CERROR("Refusing connection from %u.%u.%u.%u: "
                               "insecure port %d\n",
                               HIPQUAD(peer_ip), peer_port);
                        goto failed;
                }

                rc = libcfs_sock_read(newsock, &magic, sizeof(magic),
                                      accept_timeout);
                if (rc != 0) {
                        CERROR("Error %d reading connection request from "
                               "%u.%u.%u.%u\n", rc, HIPQUAD(peer_ip));
                        goto failed;
                }

                rc = lnet_accept(newsock, magic);
                if (rc != 0)
                        goto failed;

                continue;

        failed:
                libcfs_sock_release(newsock);
        }

        libcfs_sock_release(lnet_acceptor_state.pta_sock);
        lnet_acceptor_state.pta_sock = NULL;

        CDEBUG(D_NET, "Acceptor stopping\n");

        /* unblock lnet_acceptor_stop() */
        cfs_mt_complete(&lnet_acceptor_state.pta_signal);
        return 0;
}

static inline int
accept2secure(const char *acc, long *sec)
{
        if (!strcmp(acc, "secure")) {
                *sec = 1;
                return 1;
        } else if (!strcmp(acc, "all")) {
                *sec = 0;
                return 1;
        } else if (!strcmp(acc, "none")) {
                return 0;
        } else {
                LCONSOLE_ERROR_MSG(0x124, "Can't parse 'accept=\"%s\"'\n",
                                   acc);
                return -EINVAL;
        }
}

int
lnet_acceptor_start(void)
{
        int  rc;
        long rc2;
        long secure;

        LASSERT (lnet_acceptor_state.pta_sock == NULL);

        rc = lnet_acceptor_get_tunables();
        if (rc != 0)
                return rc;

#ifndef __KERNEL__
        /* Do nothing if we're liblustre clients */
        if ((the_lnet.ln_pid & LNET_PID_USERFLAG) != 0)
                return 0;
#endif

        cfs_mt_init_completion(&lnet_acceptor_state.pta_signal);
        rc = accept2secure(accept_type, &secure);
        if (rc <= 0) {
                cfs_mt_fini_completion(&lnet_acceptor_state.pta_signal);
                return rc;
        }

        if (lnet_count_acceptor_nis() == 0)  /* not required */
                return 0;

        rc2 = cfs_create_thread(lnet_acceptor, (void *)(ulong_ptr_t)secure, 0);
        if (rc2 < 0) {
                CERROR("Can't start acceptor thread: %d\n", rc);
                cfs_mt_fini_completion(&lnet_acceptor_state.pta_signal);

                return -ESRCH;
        }

        /* wait for acceptor to startup */
        cfs_mt_wait_for_completion(&lnet_acceptor_state.pta_signal);

        if (!lnet_acceptor_state.pta_shutdown) {
                /* started OK */
                LASSERT (lnet_acceptor_state.pta_sock != NULL);
                return 0;
        }

        LASSERT (lnet_acceptor_state.pta_sock == NULL);
        cfs_mt_fini_completion(&lnet_acceptor_state.pta_signal);

        return -ENETDOWN;
}

void
lnet_acceptor_stop(void)
{
        if (lnet_acceptor_state.pta_sock == NULL) /* not running */
                return;

        lnet_acceptor_state.pta_shutdown = 1;
        libcfs_sock_abort_accept(lnet_acceptor_state.pta_sock);

        /* block until acceptor signals exit */
        cfs_mt_wait_for_completion(&lnet_acceptor_state.pta_signal);

        cfs_mt_fini_completion(&lnet_acceptor_state.pta_signal);
}

#else /* single-threaded user-space */
int
lnet_acceptor_start(void)
{
        return 0;
}

void
lnet_acceptor_stop(void)
{
}
#endif /* defined(__KERNEL__) || defined(HAVE_LIBPTHREAD) */
