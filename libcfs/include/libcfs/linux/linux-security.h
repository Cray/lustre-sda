/*
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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#define SID_CACHE_SIZE 512
typedef struct hlist_head cfs_sid_cache_t[SID_CACHE_SIZE];

int cfs_get_current_sid(__u32 *sid);
int cfs_get_current_crsid(__u32 *sid);
int cfs_set_current_sid(__u32 sid);
int cfs_sid_to_string(__u32 sid, char *str);
int cfs_string_to_sid(__u32 *sid, char *str, int len);
int cfs_string_to_sid_default(__u32 *sid, __u32 def_sid, char *str, int len);
int cfs_lsid_to_rsid(__u32 lsid, __u32 *rsid, cfs_sid_cache_t cache);
int cfs_sid_cache_init(cfs_sid_cache_t **cache);
void cfs_sid_cache_fini(cfs_sid_cache_t *cache);
int cfs_sid_cache_add(__u32 lsid, __u32 rsid, cfs_sid_cache_t cache);
int cfs_sid_cache_del(__u32 lsid, cfs_sid_cache_t cache);

int cfs_security_create(__u32 tsid, __u32 tcsid, __u32 dsid, __u32 sbsid, umode_t mode, char *name);
int cfs_security_link(__u32 tsid, __u32 dsid, __u32 isid, umode_t mode, char *name);
int cfs_security_rename(__u32 tsid, char *old_name, char *new_name,
			   __u32 old_dsid, __u32 old_isid,
			   __u32 new_dsid, __u32 new_isid,
			   umode_t old_imode, umode_t new_imode,
			   bool same_dirs, int new_i_exists);
int cfs_security_unlink(__u32 tsid, __u32 dsid, __u32 isid, umode_t mode, char *name);
int cfs_security_readlink(__u32 tsid, __u32 osid, umode_t mode, char *name);
int cfs_security_permission(__u32 tsid, __u32 osid, int mode, int mask, char *name);
int cfs_security_setattr(__u32 tsid, __u32 osid, umode_t mode,
			    struct iattr *iattr, char *name);
int cfs_security_getattr(__u32 tsid, __u32 osid, umode_t mode, char *name);
int cfs_security_setxattr(__u32 tsid, __u32 sbsid, __u32 isid,
			  umode_t mode, char *fname,
			  const void *value, size_t size, char *name,
			  __u64 capa, __u32 fsuid, __u32 iuid);
int cfs_security_removexattr(__u32 tsid, __u32 isid, umode_t mode,
			     char *fname, char *name, __u64 capa);
int cfs_security_getxattr(__u32 tsid, __u32 osid, umode_t mode, char *name);
int cfs_security_listxattr(__u32 tsid, __u32 osid, umode_t mode, char *name);
int cfs_security_open(__u32 tsid, __u32 osid, umode_t mode, fmode_t fmode, unsigned fflags, char *name);
int cfs_security_lock(__u32 tsid, __u32 osid, __u32 fsid, umode_t mode, char *name);

int cfs_security_init_object(__u32 msid, __u32 dsid,
			     __u32 tsid, __u32 tcsid, umode_t mode,
			     char **name, void **value,
			     size_t *len);
void cfs_invalidate_inode_sid(struct inode *);
void cfs_get_sb_security(struct super_block *sb, __u32 *sid, __u32 *def_sid);
