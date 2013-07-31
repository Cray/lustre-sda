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


#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/lsm_audit.h>
#include <av_permissions.h>
#include <flask.h>
#include <objsec.h>
#include <avc.h>
#include <security.h>

#include <libcfs/libcfs.h>
#include <libcfs/list.h>

struct cfs_sid_cache_node {
	__u32			lsid;
	__u32			rsid;
	cfs_hlist_node_t	node;
};

void cfs_invalidate_inode_sid(struct inode *inode)
{
	struct inode_security_struct *isec = inode->i_security;

	/* XXX: Very racy, but the caller should be aware ... */
	isec->initialized = 0;
}

void cfs_get_sb_security(struct super_block *sb, __u32 *sid, __u32 *def_sid)
{
	struct superblock_security_struct *sbsec = sb->s_security;

	*sid = sbsec->sid;
	*def_sid = sbsec->def_sid;
}

/* XXX: need a kernel header */

#define MAY_LINK	0
#define MAY_UNLINK	1
#define MAY_RMDIR	2

static inline u16 inode_mode_to_security_class(umode_t mode)
{
	switch (mode & S_IFMT) {
	case S_IFSOCK:
		return SECCLASS_SOCK_FILE;
	case S_IFLNK:
		return SECCLASS_LNK_FILE;
	case S_IFREG:
		return SECCLASS_FILE;
	case S_IFBLK:
		return SECCLASS_BLK_FILE;
	case S_IFDIR:
		return SECCLASS_DIR;
	case S_IFCHR:
		return SECCLASS_CHR_FILE;
	case S_IFIFO:
		return SECCLASS_FIFO_FILE;

	}

	return SECCLASS_FILE;
}

/* Convert a Linux file to an access vector. */
static inline u32 file_to_av(fmode_t fmode, unsigned fflags)
{
	u32 av = 0;

	if (fmode & FMODE_READ)
		av |= FILE__READ;
	if (fmode & FMODE_WRITE) {
		if (fflags & O_APPEND)
			av |= FILE__APPEND;
		else
			av |= FILE__WRITE;
	}
	if (!av) {
		/*
		 * Special file opened with flags 3 for ioctl-only use.
		 */
		av = FILE__IOCTL;
	}

	return av;
}

static inline u32 open_inode_to_av(unsigned mode)
{
	if (selinux_policycap_openperm) {
		/*
		 * lnk files and socks do not really have an 'open'
		 */
		if (S_ISREG(mode))
			return FILE__OPEN;
		else if (S_ISCHR(mode))
			return CHR_FILE__OPEN;
		else if (S_ISBLK(mode))
			return BLK_FILE__OPEN;
		else if (S_ISFIFO(mode))
			return FIFO_FILE__OPEN;
		else if (S_ISDIR(mode))
			return DIR__OPEN;
		else if (S_ISSOCK(mode))
			return SOCK_FILE__OPEN;
		else
			printk(KERN_ERR "SELinux: WARNING: inside %s with "
				"unknown mode:%o\n", __func__, mode);
	}

	return 0;
}

/*
 * Convert a file to an access vector and include the correct open
 * open permission.
 */
static inline u32 open_file_to_av(fmode_t fmode, unsigned fflags, unsigned imode)
{
	u32 av = file_to_av(fmode, fflags);

	av |= open_inode_to_av(imode);

	return av;
}

static inline u32 file_mask_to_av(int mode, int mask)
{
	u32 av = 0;

	if ((mode & S_IFMT) != S_IFDIR) {
		if (mask & MAY_EXEC)
			av |= FILE__EXECUTE;
		if (mask & MAY_READ)
			av |= FILE__READ;

		if (mask & MAY_APPEND)
			av |= FILE__APPEND;
		else if (mask & MAY_WRITE)
			av |= FILE__WRITE;

	} else {
		if (mask & MAY_EXEC)
			av |= DIR__SEARCH;
		if (mask & MAY_WRITE)
			av |= DIR__WRITE;
		if (mask & MAY_READ)
			av |= DIR__READ;
	}

	return av;
}
/* End of kernel headers */

static inline int cfs_sid_hashfn(__u32 sid)
{
	return sid % SID_CACHE_SIZE;
}

/*
 * Get SID of the current thread.
 * @sid - a pointer where to store SID
 * Returns:
 *           0 - on success
 * -EOPNOTSUPP - no SELINUX enabled
 */
int cfs_get_current_sid(__u32 *sid)
{
	struct task_security_struct *tsec;

	if (!selinux_is_enabled())
		return -EOPNOTSUPP;

	tsec = current_cred()->security;
	*sid = tsec->sid;

	return 0;
}

/*
 * Get creation SID of the current thread.
 * @sid - a pointer where to store SID
 * Returns:
 *           0 - on success
 * -EOPNOTSUPP - no SELINUX enabled
 */
int cfs_get_current_crsid(__u32 *sid)
{
	struct task_security_struct *tsec;

	if (!selinux_is_enabled())
		return -EOPNOTSUPP;

	tsec = current_cred()->security;
	*sid = tsec->create_sid;

	return 0;
}

/*
 * Set SID for the current thread.
 * @sid - SID value
 * Returns:
 *           0 - on success
 * -EOPNOTSUPP - no SELINUX enabled
 */
int cfs_set_current_sid(__u32 sid)
{
	struct task_security_struct *tsec;

	if (!selinux_is_enabled())
		return -EOPNOTSUPP;

	tsec = current_cred()->security;
	tsec->sid = tsec->osid = sid;

	return 0;
}

/*
 * Convert SID into string
 * @sid - the SID value to convert
 * @str - ptr where to put the security string
 * Returns:
 *           0 - on success
 * -EOPNOTSUPP - no SELINUX enabled
 */
int cfs_sid_to_string(__u32 sid, char *str)
{
	int rc;
	__u32 len;
	char *s;

	if (!selinux_is_enabled())
		return -EOPNOTSUPP;

	rc = security_sid_to_context(sid, &s, &len);
	if (rc == 0) {
		memcpy(str, s, len); str[len] = 0;
		kfree(s);
		/* printk("converted SID %d to string %s\n", sid, str); */
	} else {
		printk("unable to convert SID %d to string, rc=%d\n", sid, rc);
	}

	return rc;
}

/*
 * Convert security context string into SID
 * @sid - the SID pointer
 * @str - the security context string
 * Returns:
 *           0 - on success
 * -EOPNOTSUPP - no SELINUX enabled
 */
int cfs_string_to_sid(__u32 *sid, char *str, int len)
{
	int rc;

	if (!selinux_is_enabled())
		return -EOPNOTSUPP;

	rc = security_context_to_sid(str, len, sid);
	if (rc == 0) {
		/* printk("converted %.*s to SID %d\n", len, str, *sid); */
	} else {
		printk("unable to convert %.*s to SID, rc=%d\n", len, str, rc);
	}

	return rc;
}

/*
 * Convert security context string into SID
 * @sid - the SID pointer
 * @str - the security context string
 * Returns:
 *           0 - on success
 * -EOPNOTSUPP - no SELINUX enabled
 */
int cfs_string_to_sid_default(__u32 *sid, __u32 def_sid, char *str, int len)
{
	int rc;

	if (!selinux_is_enabled())
		return -EOPNOTSUPP;

	rc = security_context_to_sid_default(str, len, sid, def_sid, GFP_NOFS);
	if (rc == 0) {
		/* printk("converted %.*s to SID %d\n", len, str, *sid); */
	} else {
		printk("unable to convert %.*s to SID, rc=%d\n", len, str, rc);
	}

	return rc;
}

/* Convert local SID to remote SID
 * @lsid  - local sid
 * @rsid  - remote sid ptr
 * @cache - ptr to cache
 * Returns:
 *       0 - on success
 * -ENOENT - if not found in cache
 */
int cfs_lsid_to_rsid(__u32 lsid, __u32 *rsid, cfs_sid_cache_t cache)
{
	int hash = cfs_sid_hashfn(lsid);
	struct cfs_sid_cache_node *node;
	cfs_hlist_node_t *n;

	cfs_hlist_for_each_entry(node, n, &cache[hash], node) {
		if (node->lsid == lsid) {
			*rsid = node->rsid;
			return 0;
		}
	}

	return -ENOENT;
}

/*
 * Initialize empty SID translation cache.
 * @cache - ptr to cache holder
 * Returns:
 *       0 - on success
 * -ENOMEM - on no memory
 */
int cfs_sid_cache_init(cfs_sid_cache_t **cache)
{
	int i;

	*cache = (cfs_sid_cache_t *)cfs_alloc(sizeof(**cache), CFS_ALLOC_IO);
	if (*cache == NULL)
		return -ENOMEM;

	for (i = 0; i < SID_CACHE_SIZE; i++)
		CFS_INIT_HLIST_HEAD(&(**cache)[i]);

	return 0;
}

/*
 * Free cache
 * @cache - cache ptr
 */
void cfs_sid_cache_fini(cfs_sid_cache_t *cache)
{
	int i;
	struct cfs_sid_cache_node *node;
	cfs_hlist_node_t *n, *n2;

	for (i = 0; i < SID_CACHE_SIZE; i++) {
		cfs_hlist_for_each_entry_safe(node, n, n2, &(*cache)[i], node) {
			cfs_hlist_del(&node->node);
			cfs_free(node);
		}
	}

	cfs_free(*cache);
}

/*
 * Add LSID->RSID translation to the SID cache
 * @cache - cache ptr
 * Returns:
 *   -ENOMEM on no memory
 *   0       on success
 */
int cfs_sid_cache_add(__u32 lsid, __u32 rsid, cfs_sid_cache_t cache)
{
	struct cfs_sid_cache_node *node;
	int hash;

	node = cfs_alloc(sizeof(*node), CFS_ALLOC_IO);
	if (node == NULL)
		return -ENOMEM;

	hash = cfs_sid_hashfn(lsid);
	node->lsid = lsid;
	node->rsid = rsid;
	cfs_hlist_add_head(&node->node, &cache[hash]);

	return 0;
}

/*
 * Delete translation from cache
 * @lsid  - local SID
 * @cache - cache ptr
 * Returns:
 *       0 - on success
 * -ENOENT - if not found
 */
int cfs_sid_cache_del(__u32 lsid, cfs_sid_cache_t cache)
{
	int hash = cfs_sid_hashfn(lsid);
	struct cfs_sid_cache_node *node;
	struct hlist_node *n;

	cfs_hlist_for_each_entry(node, n, &cache[hash], node) {
		if (node->lsid == lsid) {
			cfs_hlist_del(&node->node);
			cfs_free(node);
			return 0;
		}
	}

	return -ENOENT;
}

#define DEFINE_CAD(n,ad,_t)              \
	struct dentry __d ## n = { .d_name = { .name = (n)} };       \
	struct common_audit_data ad = { .u = { .fs = { .path = { .dentry = &__d ## n }}}, \
					.type = LSM_AUDIT_DATA_##_t }

/*
 * XXX: Copy&paste from the kernel.
 * Check whether a task can create a file.
 */
static int may_create(__u32 tsid, __u32 tcsid,
		      __u32 dsid, __u32 sbsid,
		      u16 tclass, char *name)
{
	int rc;
	DEFINE_CAD(name,ad,FS);

	rc = avc_has_perm(tsid, dsid, SECCLASS_DIR,
			  DIR__ADD_NAME | DIR__SEARCH,
			  &ad);
	if (rc)
		return rc;

	if (!tcsid) { /* XXX: Assume SE_SBLABELSUPP */
		rc = security_transition_sid(tsid, dsid, tclass, &tcsid);
		if (rc)
			return rc;
	}

	rc = avc_has_perm(tsid, tcsid, tclass, FILE__CREATE, &ad);
	if (rc)
		return rc;

	return avc_has_perm(tcsid, sbsid,
			    SECCLASS_FILESYSTEM,
			    FILESYSTEM__ASSOCIATE, &ad);
}

static int may_link(__u32 tsid, __u32 dsid, __u32 isid, umode_t mode, int kind, char *name)
{
	u32 av;
	int rc;
	DEFINE_CAD(name,ad,FS);

	av = DIR__SEARCH;
	av |= (kind ? DIR__REMOVE_NAME : DIR__ADD_NAME);
	rc = avc_has_perm(tsid, dsid, SECCLASS_DIR, av, &ad);
	if (rc)
		return rc;

	switch (kind) {
	case MAY_LINK:
		av = FILE__LINK;
		break;
	case MAY_UNLINK:
		av = FILE__UNLINK;
		break;
	case MAY_RMDIR:
		av = DIR__RMDIR;
		break;
	default:
		printk(KERN_WARNING "SELinux: %s:  unrecognized kind %d\n",
			__func__, kind);
		return 0;
	}

	rc = avc_has_perm(tsid, isid, inode_mode_to_security_class(mode),
			  av, &ad);
	return rc;
}

/*
 * Check inode_create security
 * Same for inode_mknod/inode_mkdir/inode_link
 * @tsid  - Task SID
 * @tcsid - Creation SID
 * @dsid  - Parent directory SID
 * @sbsid - Superblock SID
 * @mode  - mode (S_IF*)
 * @name  - name passed to audit
 * Returns:
 * 0 - on success
 */
int cfs_security_create(__u32 tsid, __u32 tcsid, __u32 dsid,
			__u32 sbsid, umode_t mode, char *name)
{
	if (!selinux_is_enabled())
		return -EOPNOTSUPP;

	return may_create(tsid, tcsid, dsid, sbsid,
			  inode_mode_to_security_class(mode), name);
}

/*
* Check inode_link security
* @tsid - Task SID
* @dsid - parent directory SID
* @isid - inode SID
* @mode - mode
* @name - name passed to audit
* Returns:
* 0 - on success
*/
int cfs_security_link(__u32 tsid, __u32 dsid, __u32 isid,
		      umode_t mode, char *name)
{
	if (!selinux_is_enabled())
		return -EOPNOTSUPP;

	return may_link(tsid, dsid, isid, mode, MAY_LINK, name);
}

/* 
 * Check inode_rename security
 * @tsid  - Task SID
 * @old_name - old dentry name
 * @new_name - new dentry name
 * @old_dsid - old directory SID
 * @old_isid - old dentry SID
 * @new_dsid - new directory SID
 * @new_isid - new dentry SID
 * @old_imode - old dentry mode
 * @new_imode - new dentry mode
 * @same_dirs - true if source and target dirs are the same
 * @new_i_exists - true if replacing an existing dentry
 * Returns:
 * 0 - on success
 */
int cfs_security_rename(__u32 tsid, char *old_name, char *new_name,
			__u32 old_dsid, __u32 old_isid,
			__u32 new_dsid, __u32 new_isid,
			umode_t old_imode, umode_t new_imode,
			bool same_dirs, int new_i_exists)
{
	u32 av;
	int rc;
	DEFINE_CAD(old_name,ad1,FS);
	DEFINE_CAD(new_name,ad2,FS);

	if (!selinux_is_enabled())
		return -EOPNOTSUPP;

	rc = avc_has_perm(tsid, old_dsid, SECCLASS_DIR,
			  DIR__REMOVE_NAME | DIR__SEARCH, &ad1);
	if (rc)
		return rc;
	rc = avc_has_perm(tsid, old_isid,
			  inode_mode_to_security_class(old_imode),
			  FILE__RENAME, &ad1);
	if (rc)
		return rc;
	if (S_ISDIR(old_imode) && !same_dirs) {
		rc = avc_has_perm(tsid, old_isid,
				  inode_mode_to_security_class(old_imode),
				  DIR__REPARENT, &ad1);
		if (rc)
			return rc;
	}

	av = DIR__ADD_NAME | DIR__SEARCH;
	if (new_i_exists)
		av |= DIR__REMOVE_NAME;
	rc = avc_has_perm(tsid, new_dsid, SECCLASS_DIR, av, &ad2);
	if (rc)
		return rc;
	if (new_i_exists) {
		rc = avc_has_perm(tsid, new_isid,
				  inode_mode_to_security_class(new_imode),
				  (S_ISDIR(new_imode) ? DIR__RMDIR : FILE__UNLINK),
				  &ad2);
		if (rc)
			return rc;
	}

	return 0;
}

/*
 * Check inode_unlink security
 * @tsid - Task SID
 * @dsid - parent directory SID
 * @isid - inode SID
 * @mode - mode
 * @name  - name passed to audit
 * Returns:
 * 0 - on success
 */
int cfs_security_unlink(__u32 tsid, __u32 dsid, __u32 isid,
			umode_t mode, char *name)
{
	if (!selinux_is_enabled())
		return -EOPNOTSUPP;

	return may_link(tsid, dsid, isid, mode, MAY_UNLINK, name);
}

/*
 * Check inode_readlink security
 * @tsid - Task SID
 * @osid - link SID
 * @mode - link mode (should probably always be link?)
 * @name - link file name (for audit)
 * Returns:
 * 0 - on success
 */
int cfs_security_readlink(__u32 tsid, __u32 osid, umode_t mode, char *name)
{
	DEFINE_CAD(name,ad,FS);

	if (!selinux_is_enabled())
		return -EOPNOTSUPP;

	return avc_has_perm(tsid, osid, inode_mode_to_security_class(mode),
			    FILE__READ, &ad);
}

/*
 * Check inode_permission security.
 * @tsid - Task SID
 * @osid - object SID
 * @mode - object mode
 * @mask - permission access bits
 * @name - object name (for audit)
 * Returns:
 * 0 - on success
 */
int cfs_security_permission(__u32 tsid, __u32 osid, int mode,
			    int mask, char *name)
{
	DEFINE_CAD(name,ad,FS);

	if (!selinux_is_enabled())
		return -EOPNOTSUPP;

	if (!mask) {
		/* No permission to check.  Existence test. */
		return 0;
	}

	return avc_has_perm(tsid, osid, inode_mode_to_security_class(mode),
			    file_mask_to_av(mode, mask), &ad);
}

/*
 * Check inode_setattr security.
 * @tsid - Task SID
 * @osid - object SID
 * @mode - object mode
 * @iattr - new attributes
 * @name - object name (for audit)
 * Returns:
 * 0 - on success
 */
int cfs_security_setattr(__u32 tsid, __u32 osid, umode_t mode,
			    struct iattr *iattr, char *name)
{
	unsigned int ia_valid = iattr->ia_valid;
	__u32 av;
	DEFINE_CAD(name,ad,FS);

	if (!selinux_is_enabled())
		return -EOPNOTSUPP;

	/* ATTR_FORCE is just used for ATTR_KILL_S[UG]ID. */
	if (ia_valid & ATTR_FORCE) {
		ia_valid &= ~(ATTR_KILL_SUID | ATTR_KILL_SGID | ATTR_MODE |
			      ATTR_FORCE);
		if (!ia_valid)
			return 0;
	}

	if (ia_valid & (ATTR_MODE | ATTR_UID | ATTR_GID |
			ATTR_ATIME_SET | ATTR_MTIME_SET | ATTR_TIMES_SET))
		av = FILE__SETATTR;
	else
		av = FILE__WRITE;

	return avc_has_perm(tsid, osid, inode_mode_to_security_class(mode),
			    av, &ad);
}

/*
 * Check inode_getattr security.
 * @tsid - Task SID
 * @osid - object SID
 * @mode - object mode
 * @name - object name (for audit)
 * Returns:
 * 0 - on success
 */
int cfs_security_getattr(__u32 tsid, __u32 osid, umode_t mode, char *name)
{
	DEFINE_CAD(name,ad,FS);

	if (!selinux_is_enabled())
		return -EOPNOTSUPP;

	return avc_has_perm(tsid, osid, inode_mode_to_security_class(mode),
			    FILE__GETATTR, &ad);
}

#include <linux/xattr.h>
#define XATTR_SELINUX_SUFFIX "selinux"
#define XATTR_NAME_SELINUX XATTR_SECURITY_PREFIX XATTR_SELINUX_SUFFIX

/*
 * Check inode_setxattr security.
 * @tsid  - Task SID
 * @sbsid - superblock SID
 * @isid  - inode SID
 * @mode  - inode mode
 * @fname - file name (for audit)
 * @name  - EA name
 * @value - EA value
 * @size  - EA value size
 * @capa  - task capabilities
 * @fsuid - Task fsuid
 * @iuid  - inode UID
 * Returns:
 * 0 - on success
 */
int cfs_security_setxattr(__u32 tsid, __u32 sbsid, __u32 isid,
			  umode_t mode, char *fname,
			  const void *value, size_t size, char *name,
			  __u64 capa, __u32 fsuid, __u32 iuid)
{
	DEFINE_CAD(fname,ad,FS);
	u32 newsid;
	int rc = 0;

	if (!selinux_is_enabled())
		return -EOPNOTSUPP;

	if (strcmp(name, XATTR_NAME_SELINUX)) {
		if (!strncmp(name, XATTR_SECURITY_PREFIX,
			     sizeof XATTR_SECURITY_PREFIX - 1)) {
			if (!strcmp(name, XATTR_NAME_CAPS)) {
				if (!(capa & (1 << CFS_CAP_SETFCAP)))
					return -EPERM;
			} else if (!(capa & (1 << CFS_CAP_SYS_ADMIN))) {
				/* A different attribute in the security namespace.
				   Restrict to administrator. */
				return -EPERM;
			}
		}

		return avc_has_perm(tsid, isid,
				    inode_mode_to_security_class(mode),
				    FILE__SETATTR, &ad);
	}

	if (!(fsuid == iuid || capa & (1 << CFS_CAP_FOWNER)))
		return -EPERM;

	rc = avc_has_perm(tsid, isid, inode_mode_to_security_class(mode),
			  FILE__RELABELFROM, &ad);
	if (rc)
		return rc;

	rc = security_context_to_sid(value, size, &newsid);
	if (rc == -EINVAL) {
//		if (!(capa & (1 << CFS_CAP_MAC_ADMIN)))
//			return rc;
		rc = security_context_to_sid_force(value, size, &newsid);
	}
	if (rc)
		return rc;

	rc = avc_has_perm(tsid, newsid, inode_mode_to_security_class(mode),
			  FILE__RELABELTO, &ad);
	if (rc)
		return rc;

	rc = security_validate_transition(isid, newsid, tsid,
					  inode_mode_to_security_class(mode));
	if (rc)
		return rc;

	return avc_has_perm(newsid,
			    sbsid,
			    SECCLASS_FILESYSTEM,
			    FILESYSTEM__ASSOCIATE,
			    &ad);
}

/*
 * Check inode_removexattr security.
 * @tsid  - Task SID
 * @isid  - inode SID
 * @mode  - inode mode
 * @fname - file name (for audit)
 * @name  - EA name
 * @capa  - task capabilities
 * Returns:
 * 0 - on success
 */
int cfs_security_removexattr(__u32 tsid, __u32 isid, umode_t mode,
			     char *fname, char *name, __u64 capa)
{
	DEFINE_CAD(fname,ad,FS);

	if (!selinux_is_enabled())
		return -EOPNOTSUPP;

	if (!strcmp(name, XATTR_NAME_SELINUX))
		return -EACCES;

	if (!strncmp(name, XATTR_SECURITY_PREFIX,
		     sizeof XATTR_SECURITY_PREFIX - 1)) {
		if (!strcmp(name, XATTR_NAME_CAPS)) {
			if (!(capa & (1 << CFS_CAP_SETFCAP)))
				return -EPERM;
		} else if (!(capa & (1 << CFS_CAP_SYS_ADMIN))) {
			/* A different attribute in the security namespace.
			   Restrict to administrator. */
			return -EPERM;
		}
	}

	return avc_has_perm(tsid, isid,
			    inode_mode_to_security_class(mode),
			    FILE__SETATTR, &ad);
}

/*
 * Check inode_getxattr security.
 * @tsid - Task SID
 * @osid - object SID
 * @mode - object mode
 * @name - object name (for audit)
 * Returns:
 * 0 - on success
 */
int cfs_security_getxattr(__u32 tsid, __u32 osid, umode_t mode, char *name)
{
	DEFINE_CAD(name,ad,FS);

	if (!selinux_is_enabled())
		return -EOPNOTSUPP;

	return avc_has_perm(tsid, osid, inode_mode_to_security_class(mode),
			    FILE__GETATTR, &ad);
}

/*
 * Check inode_listxattr security.
 * @tsid - Task SID
 * @osid - object SID
 * @mode - object mode
 * @name - object name (for audit)
 * Returns:
 * 0 - on success
 */
int cfs_security_listxattr(__u32 tsid, __u32 osid, umode_t mode, char *name)
{
	DEFINE_CAD(name,ad,FS);

	if (!selinux_is_enabled())
		return -EOPNOTSUPP;

	return avc_has_perm(tsid, osid, inode_mode_to_security_class(mode),
			    FILE__GETATTR, &ad);
}

/* Check dentry_open security.
 * @tsid   - Task SID
 * @osid   - object SID
 * @mode   - object mode
 * @fmode  - file open flags (FMODE_READ/FMODE_WRITE)
 * @fflags - file flags (O_APPEND)
 * @name   - object name (for audit)
 * Returns:
 * 0 - on success
 */
int cfs_security_open(__u32 tsid, __u32 osid, umode_t mode,
		      fmode_t fmode, unsigned fflags, char *name)
{
	DEFINE_CAD(name,ad,FS);

	if (!selinux_is_enabled())
		return -EOPNOTSUPP;

	/* XXX: see seqno in dentry_open */
	return avc_has_perm(tsid, osid, inode_mode_to_security_class(mode),
			    open_file_to_av(fmode, fflags, mode), &ad);
}

/*
 * Check file_lock security.
 * @tsid - Task SID
 * @osid - object SID
 * @fsid - FD SID
 * @mode - object mode
 * @name - object name (for audit)
 * Returns:
 * 0 - on success
 */
int cfs_security_lock(__u32 tsid, __u32 osid, __u32 fsid,
		      umode_t mode, char *name)
{
	int rc;
	DEFINE_CAD(name,ad,FS);

	if (!selinux_is_enabled())
		return -EOPNOTSUPP;

	if (tsid != fsid) {
		rc = avc_has_perm(tsid, fsid, SECCLASS_FD, FD__USE, &ad);
		if (rc)
			goto out;
	}

	rc = avc_has_perm(tsid, osid, inode_mode_to_security_class(mode),
			  FILE__LOCK, &ad);
out:
	return rc;
}

/*
 * Initialize object
 * @msid  - mount SID
 * @dsid  - directory SID
 * @tsid  - Task SID
 * @tcsid - create SID
 * @mode  - new object mode
 * @name  - xattr name for new object
 * @value - xattr value for new object
 * @len   - xattr value length
 * Returns:
 * 0 - on success
 */
int cfs_security_init_object(__u32 msid, __u32 dsid,
			     __u32 tsid, __u32 tcsid, umode_t mode,
			     char **name, void **value,
			     size_t *len)
{
	u32 clen;
	int rc;
	char *namep = NULL, *context;

	if (msid)
		tcsid = msid;
	else if (!tcsid) {
		rc = security_transition_sid(tsid, dsid,
					     inode_mode_to_security_class(mode),
					     &tcsid);
		if (rc)
			return rc;
	}

	if (name) {
		namep = kstrdup(XATTR_SELINUX_SUFFIX, GFP_NOFS);
		if (!namep)
			return -ENOMEM;
		*name = namep;
	}

	if (value && len) {
		rc = security_sid_to_context_force(tcsid, &context, &clen);
		if (rc) {
			kfree(namep);
			return rc;
		}
		*value = context;
		*len = clen;
	}

	return 0;
}


EXPORT_SYMBOL(cfs_get_current_sid);
EXPORT_SYMBOL(cfs_get_current_crsid);
EXPORT_SYMBOL(cfs_set_current_sid);
EXPORT_SYMBOL(cfs_sid_to_string);
EXPORT_SYMBOL(cfs_string_to_sid);
EXPORT_SYMBOL(cfs_string_to_sid_default);
EXPORT_SYMBOL(cfs_lsid_to_rsid);
EXPORT_SYMBOL(cfs_sid_cache_init);
EXPORT_SYMBOL(cfs_sid_cache_fini);
EXPORT_SYMBOL(cfs_sid_cache_add);
EXPORT_SYMBOL(cfs_sid_cache_del);

EXPORT_SYMBOL(cfs_security_create);
EXPORT_SYMBOL(cfs_security_link);
EXPORT_SYMBOL(cfs_security_rename);
EXPORT_SYMBOL(cfs_security_unlink);
EXPORT_SYMBOL(cfs_security_readlink);
EXPORT_SYMBOL(cfs_security_permission);
EXPORT_SYMBOL(cfs_security_setattr);
EXPORT_SYMBOL(cfs_security_getattr);
EXPORT_SYMBOL(cfs_security_setxattr);
EXPORT_SYMBOL(cfs_security_removexattr);
EXPORT_SYMBOL(cfs_security_getxattr);
EXPORT_SYMBOL(cfs_security_listxattr);
EXPORT_SYMBOL(cfs_security_open);
EXPORT_SYMBOL(cfs_security_lock);

EXPORT_SYMBOL(cfs_security_init_object);
EXPORT_SYMBOL(cfs_invalidate_inode_sid);
EXPORT_SYMBOL(cfs_get_sb_security);
