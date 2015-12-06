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
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/xattr.h>
#include <linux/lsm_audit.h>
#include <linux/kprobes.h>

#include <obd_support.h>

unsigned int hard_security = 1;
EXPORT_SYMBOL(hard_security);

DECLARE_RWSEM(obd_secpol_rwsem);

u64 obd_security_openperm;
char obd_security_file_initcon[128] = ""; /* XXX: random size */

#include "linux-security.h"

#define SELINUX_ACCESS_FILE	"/selinux/access"
#define SELINUX_CREATE_FILE	"/selinux/create"
#define SELINUX_OPENPERMS_FILE	"/selinux/policy_capabilities/open_perms"
#define SELINUX_FILE_INITCON	"/selinux/initial_contexts/file"

/* This is NOT a copy of avd */
struct obd_security_decision {
	unsigned allowed;
	unsigned auditallow;
	unsigned auditdeny;
	unsigned seqno;
	unsigned flags;
};

/* definitions of osd.flags */
#define OSD_FLAGS_PERMISSIVE 0x0001

struct file *obd_security_file_get(char *name)
{
	struct file *file;

	file = filp_open(name, O_RDWR, 0);
	if (IS_ERR(file)) {
		CERROR("failed to open %s, rc=%ld\n", name, PTR_ERR(file));
		goto out;
	}
	/* RHEL6.5 has a bug fixed by 7d683a09990ff095a91b6e724ecee0ff8733274a */
	if ((unsigned int)file->f_dentry->d_sb->s_magic != SELINUX_MAGIC) {
		filp_close(file, 0);
		file = ERR_PTR(-EINVAL);
		CERROR("wrong magic for %s %lx\n", name,
		       file->f_dentry->d_sb->s_magic);
		goto out;
	}
out:
	return file;
}

void obd_security_file_put(struct file *file)
{
	if (!IS_ERR_OR_NULL(file))
		filp_close(file, 0);
}

int obd_security_file_read(char *name, char *value, int len)
{
	struct file *file;
	int rc;

	file = obd_security_file_get(name);
	if (IS_ERR_OR_NULL(file))
		return -ENOSYS;

	rc = file->f_op->read(file, value, len, &file->f_pos);
	if (rc < 0)
		CERROR("failed to process read request: %s, rc=%d\n", name, rc);

	obd_security_file_put(file);

	return rc;
}

int obd_security_file_read_u64(char *name, u64 *value)
{
	char buf[128]; /* XXX: random number */
	int rc;

	rc = obd_security_file_read(name, buf, sizeof(buf));
	if (rc < 0)
		return rc;

	sscanf(buf, "%llu", value);

	return 0;
}

int obd_security_from_inode(struct inode *inode, char *label)
{
	int rc;

	rc = xattr_getsecurity(inode, "selinux", label, CFS_SID_MAX_LEN);
	if (rc < 0)
		return rc;

	label[rc] = 0;

	return 0;
}
EXPORT_SYMBOL(obd_security_from_inode);

/* SELinux uses file initcon as default label */
int obd_security_file_default_label(char *seclabel)
{
	strcpy(seclabel, obd_security_file_initcon);
	return 0;
}
EXPORT_SYMBOL(obd_security_file_default_label);


static void convert_to_obd_perms(enum obd_secclass tc, unsigned *perms)
{
	unsigned obd_perms = 0;
	int j;

	for (j = 0; obd_secclass_map[tc].perm[j].name != NULL; j++) {
		if (*perms & (1 << (obd_secclass_map[tc].perm[j].policy_perm - 1)))
			obd_perms |= (1 << j);
	}

	*perms = obd_perms;
}

void obd_security_compute_av(char *scon, char *tcon,
			     enum obd_secclass tc,
			     struct obd_security_decision *osd)
{
	char buf[128]; /* XXX: random number */
	struct file *sel_access_file;
	int rc;
	u16 tclass;

	tclass = obd_secclass_map[tc].policy_class;

	sel_access_file = obd_security_file_get(SELINUX_ACCESS_FILE);
	if (IS_ERR_OR_NULL(sel_access_file))
		goto err;

	snprintf(buf, sizeof(buf), "%s %s %hu", scon, tcon, tclass);

	CDEBUG(D_SEC, "compute_av request: %s\n", buf);

	/* N.B. This requires COMPUTE_AV priviledge */
	rc = sel_access_file->f_op->write(sel_access_file, buf, sizeof(buf),
					  &sel_access_file->f_pos);
	if (rc < 0) {
		CERROR("failed to process access write request: %s, rc=%d\n", buf, rc);
		dump_stack();
		goto err;
	}

	rc = sel_access_file->f_op->read(sel_access_file, buf, sizeof(buf),
					 &sel_access_file->f_pos);
	if (rc < 0) {
		CERROR("failed to process access read request: %s, rc=%d\n", buf, rc);
		dump_stack();
		goto err;
	}

	obd_security_file_put(sel_access_file);

	buf[rc] = '\0';

	CDEBUG(D_SEC, "got reply: %s\n", buf);

	sscanf(buf, "%x ffffffff %x %x %u %x",
	       &osd->allowed, &osd->auditallow,
	       &osd->auditdeny, &osd->seqno, &osd->flags);

	convert_to_obd_perms(tc, &osd->allowed);
	convert_to_obd_perms(tc, &osd->auditallow);
	convert_to_obd_perms(tc, &osd->auditdeny);

	return;
err:
	obd_security_file_put(sel_access_file);
	osd->allowed = 0;
	osd->flags = 0;
	return;
}

#define HASH_MOD 1024
rwlock_t obd_perm_lock;
rwlock_t obd_transition_lock;

atomic_t obd_perm_hits, obd_perm_misses;
atomic_t obd_tran_hits, obd_tran_misses;

struct obd_perm_cache_entry {
	char	*scon;
	char	*tcon;
	u16	tclass;
	struct	obd_security_decision osd;
};

struct obd_transition_cache_entry {
	char	*scon;
	char	*tcon;
	u16	tclass;
	char	*rcon;
};

void obd_security_perm_init(void)
{
	rwlock_init(&obd_perm_lock);
	atomic_set(&obd_perm_hits, 0);
	atomic_set(&obd_perm_misses, 0);
}

void obd_security_transition_init(void)
{
	rwlock_init(&obd_transition_lock);
	atomic_set(&obd_tran_hits, 0);
	atomic_set(&obd_tran_misses, 0);
}

struct obd_perm_cache_entry obd_perm_cache[HASH_MOD];
struct obd_transition_cache_entry obd_transition_cache[HASH_MOD];

static int string_hash(char *s)
{
	int i, t = 0;

	for (i = 0; s[i] != 0; i++)
		t += s[i];

	return t;
}

int obd_security_perm_lookup(char *scon, char *tcon,
			     u16 tclass,
			     struct obd_security_decision *osd)
{
	int hash = (string_hash(scon) ^ string_hash(tcon) ^ tclass) % HASH_MOD;
	struct obd_perm_cache_entry *entry = &obd_perm_cache[hash];
	int rc = -ENOENT;

	read_lock(&obd_perm_lock);
	if (entry->scon && !strcmp(scon, entry->scon) &&
	    entry->tcon && !strcmp(tcon, entry->tcon) &&
	    tclass == entry->tclass) {
		*osd = entry->osd;
		atomic_inc(&obd_perm_hits);
		rc = 0;
	} else {
		atomic_inc(&obd_perm_misses);
	}
	read_unlock(&obd_perm_lock);

	return rc;
}

int obd_security_transition_lookup(char *scon, char *tcon,
				   u16 tclass, char **rcon)
{
	int hash = (string_hash(scon) ^ string_hash(tcon) ^ tclass) % HASH_MOD;
	struct obd_transition_cache_entry *entry = &obd_transition_cache[hash];
	int rc = -ENOENT;

	read_lock(&obd_transition_lock);
	if (entry->scon && !strcmp(scon, entry->scon) &&
	    entry->tcon && !strcmp(tcon, entry->tcon) &&
	    tclass == entry->tclass) {
		*rcon = kstrdup(entry->rcon, GFP_ATOMIC);
		atomic_inc(&obd_tran_hits);
		rc = 0;
	} else {
		atomic_inc(&obd_tran_misses);
	}
	read_unlock(&obd_transition_lock);

	return rc;
}

void obd_security_perm_cache(char *scon, char *tcon,
			     u16 tclass,
			     struct obd_security_decision *osd)
{
	int hash = (string_hash(scon) ^ string_hash(tcon) ^ tclass) % HASH_MOD;
	struct obd_perm_cache_entry *entry = &obd_perm_cache[hash];
	char *scon_dupe = kstrdup(scon, GFP_ATOMIC);
	char *tcon_dupe = kstrdup(tcon, GFP_ATOMIC);
	char *scon_old = NULL;
	char *tcon_old = NULL;

	if (scon_dupe == NULL || tcon_dupe == NULL)
		goto out;

	write_lock(&obd_perm_lock);
	scon_old = entry->scon;
	tcon_old = entry->tcon;
	entry->scon = scon_dupe;
	entry->tcon = tcon_dupe;
	entry->tclass = tclass;
	entry->osd = *osd;
	write_unlock(&obd_perm_lock);

out:
	if (scon_old != NULL)
		kfree(scon_old);
	if (tcon_old != NULL)
		kfree(tcon_old);
}

void obd_security_transition_cache(char *scon, char *tcon,
				   u16 tclass, char *rcon)
{
	int hash = (string_hash(scon) ^ string_hash(tcon) ^ tclass) % HASH_MOD;
	struct obd_transition_cache_entry *entry = &obd_transition_cache[hash];
	char *scon_dupe = kstrdup(scon, GFP_ATOMIC);
	char *tcon_dupe = kstrdup(tcon, GFP_ATOMIC);
	char *rcon_dupe = kstrdup(rcon, GFP_ATOMIC);
	char *scon_old = NULL;
	char *tcon_old = NULL;
	char *rcon_old = NULL;

	if (scon_dupe == NULL || tcon_dupe == NULL || rcon_dupe == NULL)
		goto out;

	write_lock(&obd_transition_lock);
	scon_old = entry->scon;
	tcon_old = entry->tcon;
	rcon_old = entry->rcon;
	entry->scon = scon_dupe;
	entry->tcon = tcon_dupe;
	entry->rcon = rcon_dupe;
	entry->tclass = tclass;
	write_unlock(&obd_transition_lock);

out:
	if (scon_old != NULL)
		kfree(scon_old);
	if (tcon_old != NULL)
		kfree(tcon_old);
	if (rcon_old != NULL)
		kfree(rcon_old);
}

void obd_security_perm_fini(void)
{
	int i, num = 0;

	for (i = 0; i < HASH_MOD; i++) {
		if (obd_perm_cache[i].scon != NULL) {
			kfree(obd_perm_cache[i].scon);
			num++;
		}
		if (obd_perm_cache[i].tcon != NULL)
			kfree(obd_perm_cache[i].tcon);
	}

	memset(obd_perm_cache, 0, sizeof(obd_perm_cache));

	LCONSOLE_INFO("Purged %d security permission cache entries "
		      "(%d hits, %d misses)\n", num,
		      atomic_read(&obd_perm_hits),
		      atomic_read(&obd_perm_misses));
}

void obd_security_transition_fini(void)
{
	int i, num = 0;

	for (i = 0; i < HASH_MOD; i++) {
		if (obd_transition_cache[i].scon != NULL) {
			kfree(obd_transition_cache[i].scon);
			num++;
		}
		if (obd_transition_cache[i].tcon != NULL)
			kfree(obd_transition_cache[i].tcon);
		if (obd_transition_cache[i].rcon != NULL)
			kfree(obd_transition_cache[i].rcon);
	}

	memset(obd_transition_cache, 0, sizeof(obd_transition_cache));

	LCONSOLE_INFO("Purged %d security transition cache entries "
		      "(%d hits, %d misses)\n", num,
		      atomic_read(&obd_tran_hits),
		      atomic_read(&obd_tran_misses));
}

int obd_security_has_perm_noaudit(char *scon, char *tcon,
				  u16 tclass, u32 requested,
				  struct obd_security_decision *osd)
{
	int rc = 0;

	BUG_ON(!requested);

	rc = obd_security_perm_lookup(scon, tcon, tclass, osd);
	if (rc != 0) {
		obd_security_compute_av(scon, tcon, tclass, osd);
		obd_security_perm_cache(scon, tcon, tclass, osd);
		rc = 0;
	}

	if (requested & ~(osd->allowed)) {
		/*
		 * Removed selinux_enforcing check because
		 * we always want to be enforcing.
		 */
		if (osd->flags & OSD_FLAGS_PERMISSIVE) {
		} else {
			rc = -EACCES;
		}
	}

	return rc;
}

static void avc_dump_av(struct audit_buffer *ab, enum obd_secclass tclass, u32 av)
{
	struct obd_secperms_map_s *perms;
	int i, perm;

	if (av == 0) {
		audit_log_format(ab, " null");
		return;
	}

	perms = obd_secclass_map[tclass].perm;

	audit_log_format(ab, " {");
	i = 0;
	perm = 1;
	while (i < (sizeof(av) * 8)) {
		if ((perm & av) && (1 << perms[i].policy_perm)) {
			audit_log_format(ab, " %s", perms[i].name);
			av &= ~perm;
		}
		i++;
		perm <<= 1;
	}

	if (av)
		audit_log_format(ab, " 0x%x", av);

	audit_log_format(ab, " }");
}

void obd_security_audit(char *scon, char *tcon, enum obd_secclass tclass,
			  u32 requested, struct obd_security_decision *osd,
			  int result, char *path)
{
	struct audit_buffer *ab;
	u32 denied, audited;

	denied = requested & ~osd->allowed;
	if (denied)
		audited = denied & osd->auditdeny;
	else if (result)
		audited = denied = requested;
	else
		audited = requested & osd->auditallow;
	if (!audited)
		return;

	/* we use GFP_ATOMIC so we won't sleep */
	ab = audit_log_start(current->audit_context, GFP_ATOMIC, AUDIT_AVC);
	if (ab == NULL)
		return;

	audit_log_format(ab, "avc:  %s ", denied ? "denied" : "granted");
	avc_dump_av(ab, tclass, audited);
	audit_log_format(ab, " for pid=%d comm=%s name=%s "
			     "scontext=%s tcontext=%s tclass=%s",
			 current->pid, current->comm, path,
			 scon, tcon, obd_secclass_map[tclass].name);
	audit_log_end(ab);
}

int obd_security_has_perm(char *scon, char *tcon, u16 tclass,
			  u32 requested, char *path)
{
	struct obd_security_decision osd;
	int rc;

	rc = obd_security_has_perm_noaudit(scon, tcon, tclass, requested, &osd);
	obd_security_audit(scon, tcon, tclass, requested, &osd, rc, path);
	return rc;
}

int obd_security_transition(char *con, char *dcon, enum obd_secclass tc,
			    char **tcon)
{
	char buf[128]; /* XXX: random number */
	struct file *sel_create_file;
	int rc;
	u16 tclass;

	rc = obd_security_transition_lookup(con, dcon, tc, tcon);
	if (rc == 0)
		return 0;

	tclass = obd_secclass_map[tc].policy_class;

	sel_create_file = obd_security_file_get(SELINUX_CREATE_FILE);
	if (IS_ERR_OR_NULL(sel_create_file))
		return -ENOSYS;

	snprintf(buf, sizeof(buf), "%s %s %hu", con, dcon, tclass);

	CDEBUG(D_SEC, "compute_create request: %s\n", buf);

	/* N.B. This requires COMPUTE_CREATE priviledge */
	rc = sel_create_file->f_op->write(sel_create_file, buf, sizeof(buf),
					  &sel_create_file->f_pos);
	if (rc < 0) {
		CERROR("failed to process create write request: %s, rc=%d\n", buf, rc);
		goto out;
	}

	rc = sel_create_file->f_op->read(sel_create_file, buf, sizeof(buf),
					 &sel_create_file->f_pos);
	if (rc < 0) {
		CERROR("failed to process create read request: %s, rc=%d\n", buf, rc);
		goto out;
	}

	buf[rc] = '\0';

	CDEBUG(D_SEC, "got reply: %s\n", buf);

	*tcon = kstrdup(buf, GFP_NOFS);
	if (*tcon == NULL)
		rc = -ENOMEM;
	else
		rc = 0;

	obd_security_transition_cache(con, dcon, tc, *tcon);
out:
	obd_security_file_put(sel_create_file);

	return rc;
}

/**
 * \brief Check dentry_open security.
 * \param tcon The task context
 * \param ocon The object context
 * \param mode The object mode
 * \param fmode The file open flags (FMODE_READ/FMODE_WRITE)
 * \param fflags The file flags (O_APPEND)
 * \param name The object name (for audit)
 * \retval 0 success and the operation is permitted
 * \retval -EACCES operation not permitted by the policy
 */
int obd_security_check_open(char *tcon, char *ocon, umode_t mode,
			    fmode_t fmode, unsigned fflags, char *name)
{
	int rc;

	down_read(&obd_secpol_rwsem);
	rc = obd_security_has_perm(tcon, ocon,
				   inode_mode_to_security_class(mode),
				   open_file_to_av(fmode, fflags, mode), name);
	up_read(&obd_secpol_rwsem);

	return rc;
}
EXPORT_SYMBOL(obd_security_check_open);

/**
 * \brief Check inode_permission security.
 * \param tcon The task context
 * \param ocon The object context
 * \param mode The object mode
 * \param mask The permission access bits
 * \param name The object name (for audit)
 * \retval 0 success and the operation is permitted
 * \retval -EACCES operation not permitted by the policy
 */
int obd_security_check_permission(char *tcon, char *ocon, int mode,
				  int mask, char *name)
{
	int rc;

	if (!mask) {
		/* No permission to check.  Existence test. */
		return 0;
	}

	down_read(&obd_secpol_rwsem);
	rc = obd_security_has_perm(tcon, ocon,
				   inode_mode_to_security_class(mode),
				   file_mask_to_av(mode, mask), name);
	up_read(&obd_secpol_rwsem);

	return rc;
}
EXPORT_SYMBOL(obd_security_check_permission);

/**
 * \brief Check inode_setattr security.
 * \param tcon The task context
 * \param ocon The object context
 * \param mode The object mode
 * \param iattr The new attributes
 * \param name The object name (for audit)
 * \retval 0 success and the operation is permitted
 * \retval -EACCES operation not permitted by the policy
 */
int obd_security_check_setattr(char *tcon, char *ocon, umode_t mode,
			       struct iattr *iattr, char *name)
{
	unsigned int ia_valid = iattr->ia_valid;
	__u32 av;
	int rc;

	/* ATTR_FORCE is just used for ATTR_KILL_S[UG]ID. */
	if (ia_valid & ATTR_FORCE) {
		ia_valid &= ~(ATTR_KILL_SUID | ATTR_KILL_SGID | ATTR_MODE |
			      ATTR_FORCE);
		if (!ia_valid)
			return 0;
	}

	if (ia_valid & (ATTR_MODE | ATTR_UID | ATTR_GID |
			ATTR_ATIME_SET | ATTR_MTIME_SET | ATTR_TIMES_SET))
		av = 1 << OBD_SECPERM_FILE_SETATTR;
	else
		av = 1 << OBD_SECPERM_FILE_WRITE;

	down_read(&obd_secpol_rwsem);
	rc = obd_security_has_perm(tcon, ocon,
				   inode_mode_to_security_class(mode),
				   av, name);
	up_read(&obd_secpol_rwsem);

	return rc;
}
EXPORT_SYMBOL(obd_security_check_setattr);

/*
 * \brief Check inode_getattr security.
 * \param tcon The task context
 * \param ocon The object context
 * \param mode The object mode
 * \param name The object name (for audit)
 * \retval 0 success and the operation is permitted
 * \retval -EACCES operation not permitted by the policy
 */
int obd_security_check_getattr(char *tcon, char *ocon, umode_t mode, char *name)
{
	int rc;

	down_read(&obd_secpol_rwsem);
	rc = obd_security_has_perm(tcon, ocon,
				   inode_mode_to_security_class(mode),
				   1 << OBD_SECPERM_FILE_GETATTR, name);
	up_read(&obd_secpol_rwsem);

	return rc;
}
EXPORT_SYMBOL(obd_security_check_getattr);

static int may_create(char *tcon, char *tccon,
		      char *dcon, char *sbcon,
		      u16 tclass, char *name)
{
	char *tccon_calculated = NULL;
	int rc;

	rc = obd_security_has_perm(tcon, dcon, OBD_SECCLASS_DIR,
				   (1 << OBD_SECPERM_DIR_ADDNAME) |
				   (1 << OBD_SECPERM_DIR_SEARCH),
				   name);
	if (rc < 0)
		return rc;

	if (tccon == NULL) {
		rc = obd_security_transition(tcon, dcon, tclass, &tccon);
		if (rc < 0)
			return rc;

		tccon_calculated = tccon;
	}

	rc = obd_security_has_perm(tcon, tccon, tclass,
				   1 << OBD_SECPERM_FILE_CREATE, name);
	if (rc < 0)
		goto out;

	rc = obd_security_has_perm(tccon, sbcon, OBD_SECCLASS_FS,
				   1 << OBD_SECPERM_FS_ASSOCIATE, name);
out:
	if (tccon_calculated != NULL)
		kfree(tccon_calculated);

	return rc;
}

/**
 * \brief Check inode_create security
 * \brief The same for inode_mknod/inode_mkdir/inode_link
 * \param tcon The task context
 * \param tccon The creation context
 * \param dcon The parent directory context
 * \param sbcon The superblock context
 * \param mode The mode (S_IF*)
 * \param name The name passed to audit
 * \retval 0 success and the operation is permitted
 * \retval -EACCES operation not permitted by the policy
 */
int obd_security_check_create(char *tcon, char *tccon, char *dcon,
			      char *sbcon, umode_t mode, char *name)
{
	int rc;

	down_read(&obd_secpol_rwsem);
	rc = may_create(tcon, tccon, dcon, sbcon,
			inode_mode_to_security_class(mode), name);
	up_read(&obd_secpol_rwsem);

	return rc;
}
EXPORT_SYMBOL(obd_security_check_create);

/**
 * \brief Check file_lock security.
 * \param tcon The task context
 * \param ocon The object context
 * \param fcon The FD context
 * \param mode The object mode
 * \param name The object name (for audit)
 * \retval 0 success and the operation is permitted
 * \retval -EACCES operation not permitted by the policy
 */
int obd_security_check_lock(char *tcon, char *ocon, char *fcon,
			    umode_t mode, char *name)
{
	int rc;

	down_read(&obd_secpol_rwsem);

	if (strcmp(tcon, fcon)) {
		rc = obd_security_has_perm(tcon, fcon,
					   OBD_SECCLASS_FD,
					   OBD_SECPERM_FD_USE, name);
		if (rc)
			goto out;
	}

	rc = obd_security_has_perm(tcon, ocon,
				   inode_mode_to_security_class(mode),
				   OBD_SECPERM_FILE_LOCK, name);
out:
	up_read(&obd_secpol_rwsem);

	return rc;
}
EXPORT_SYMBOL(obd_security_check_lock);

#define SEC_MAY_LINK	0
#define SEC_MAY_UNLINK	1
#define SEC_MAY_RMDIR	2

static int may_link(char *tcon, char *dcon, char *icon, umode_t mode,
		    int kind, char *name)
{
	u32 av;
	int rc;

	av = 1 << OBD_SECPERM_DIR_SEARCH;
	av |= 1 << (kind ? OBD_SECPERM_DIR_REMOVENAME : OBD_SECPERM_DIR_ADDNAME);
	rc = obd_security_has_perm(tcon, dcon, OBD_SECCLASS_DIR, av, name);
	if (rc)
		return rc;

	switch (kind) {
	case SEC_MAY_LINK:
		av = 1 << OBD_SECPERM_FILE_LINK;
		break;
	case SEC_MAY_UNLINK:
		av = 1 << OBD_SECPERM_FILE_UNLINK;
		break;
	case SEC_MAY_RMDIR:
		av = 1 << OBD_SECPERM_DIR_RMDIR;
		break;
	default:
		LBUG();
	}

	rc = obd_security_has_perm(tcon, icon, inode_mode_to_security_class(mode),
				   av, name);
	return rc;
}

/**
 * \brief Check inode_link security
 * \param tcon The task context
 * \param dcon The parent directory context
 * \param icon The inode context
 * \param mode The mode
 * \param name The name passed to audit
 * \retval 0 success and the operation is permitted
 * \retval -EACCES operation not permitted by the policy
 */
int obd_security_check_link(char *tcon, char *dcon, char *icon,
			    umode_t mode, char *name)
{
	int rc;

	down_read(&obd_secpol_rwsem);
	rc = may_link(tcon, dcon, icon, mode, SEC_MAY_LINK, name);
	up_read(&obd_secpol_rwsem);

	return rc;
}
EXPORT_SYMBOL(obd_security_check_link);

/**
 * \brief Check inode_unlink security
 * \param tcon The task context
 * \param dcon The parent directory context
 * \param icon The inode context
 * \param mode The mode
 * \param name The name passed to audit
 * \retval 0 success and the operation is permitted
 * \retval -EACCES operation not permitted by the policy
 */
int obd_security_check_unlink(char *tcon, char *dcon, char *icon,
			      umode_t mode, char *name)
{
	int rc;

	down_read(&obd_secpol_rwsem);
	rc = may_link(tcon, dcon, icon, mode, SEC_MAY_UNLINK, name);
	up_read(&obd_secpol_rwsem);

	return rc;
}
EXPORT_SYMBOL(obd_security_check_unlink);

/**
 * \brief Check inode_rename security
 * \param tcon The task context
 * \param old_name The old dentry name
 * \param new_name The new dentry name
 * \param old_dcon The old directory context
 * \param old_icon The old dentry context
 * \param new_dcon The new directory context
 * \param new_icon The new dentry context
 * \param old_imode The old dentry mode
 * \param new_imode The new dentry mode
 * \param same_dirs true if source and target dirs are the same
 * \param new_i_exists true if replacing an existing dentry
 * \retval 0 success and the operation is permitted
 * \retval -EACCES operation not permitted by the policy
 */
int obd_security_check_rename(char *tcon, char *old_name, char *new_name,
			      char *old_dcon, char *old_icon,
			      char *new_dcon, char *new_icon,
			      umode_t old_imode, umode_t new_imode,
			      bool same_dirs, bool new_i_exists)
{
	u32 av;
	int rc;

	down_read(&obd_secpol_rwsem);

	rc = obd_security_has_perm(tcon, old_dcon, OBD_SECCLASS_DIR,
				   (1 << OBD_SECPERM_DIR_REMOVENAME) |
				   (1 << OBD_SECPERM_DIR_SEARCH),
				   old_name);
	if (rc)
		goto out;

	rc = obd_security_has_perm(tcon, old_icon,
			  inode_mode_to_security_class(old_imode),
			  1 << OBD_SECPERM_FILE_RENAME, old_name);
	if (rc)
		goto out;

	if (S_ISDIR(old_imode) && !same_dirs) {
		rc = obd_security_has_perm(tcon, old_icon,
				  inode_mode_to_security_class(old_imode),
				  1 << OBD_SECPERM_DIR_REPARENT, old_name);
		if (rc)
			goto out;
	}

	av = (1 << OBD_SECPERM_DIR_ADDNAME) | (1 << OBD_SECPERM_DIR_SEARCH);
	if (new_i_exists)
		av |= 1 << OBD_SECPERM_DIR_REMOVENAME;

	rc = obd_security_has_perm(tcon, new_dcon, OBD_SECCLASS_DIR, av, new_name);
	if (rc)
		goto out;

	if (new_i_exists) {
		rc = obd_security_has_perm(tcon, new_icon,
					   inode_mode_to_security_class(new_imode),
					   1<< (S_ISDIR(new_imode) ?
						OBD_SECPERM_DIR_RMDIR :
						OBD_SECPERM_FILE_UNLINK),
					   new_name);
		if (rc)
			goto out;
	}
out:
	up_read(&obd_secpol_rwsem);

	return rc;
}
EXPORT_SYMBOL(obd_security_check_rename);

/**
 * \brief Check inode_readlink security
 * \param tcon The task context
 * \param ocon The link context
 * \param mode The link mode (should probably always be link?)
 * \param name The link file name (for audit)
 * \retval 0 success and the operation is permitted
 * \retval -EACCES operation not permitted by the policy
 */
int obd_security_check_readlink(char *tcon, char *ocon, umode_t mode, char *name)
{
	int rc;

	down_read(&obd_secpol_rwsem);
	rc = obd_security_has_perm(tcon, ocon,
				   inode_mode_to_security_class(mode),
				   1 << OBD_SECPERM_FILE_READ, name);
	up_read(&obd_secpol_rwsem);

	return rc;
}
EXPORT_SYMBOL(obd_security_check_readlink);

/**
 * \brief Check sb_kern_mount security
 * \param tcon The task context
 * \param sbcon The superblock context
 * \retval 0 success and the operation is permitted
 * \retval -EACCES operation not permitted by the policy
 */
int obd_security_check_mount(char *tcon, char *sbcon, char *name)
{
	int rc;

	down_read(&obd_secpol_rwsem);
	rc = obd_security_has_perm(tcon, sbcon,
				   OBD_SECCLASS_FS,
				   1 << OBD_SECPERM_FS_MOUNT, name);
	up_read(&obd_secpol_rwsem);

	return rc;
}
EXPORT_SYMBOL(obd_security_check_mount);

/**
 * \brief Check quotactl security
 * \param tcon The task context
 * \param sbcon The superblock context
 * \retval 0 success and the operation is permitted
 * \retval -EACCES operation not permitted by the policy
 */
int obd_security_check_quotamod(char *tcon, char *sbcon, char *name)
{
	int rc;

	down_read(&obd_secpol_rwsem);
	rc = obd_security_has_perm(tcon, sbcon,
				   OBD_SECCLASS_FS,
				   1 << OBD_SECPERM_FS_QUOTAMOD, name);
	up_read(&obd_secpol_rwsem);

	return rc;
}
EXPORT_SYMBOL(obd_security_check_quotamod);

/**
 * \brief Check quotactl security
 * \param tcon The task context
 * \param sbcon The superblock context
 * \retval 0 success and the operation is permitted
 * \retval -EACCES operation not permitted by the policy
 */
int obd_security_check_getquota(char *tcon, char *sbcon, char *name)
{
	int rc;

	down_read(&obd_secpol_rwsem);
	rc = obd_security_has_perm(tcon, sbcon,
				   OBD_SECCLASS_FS,
				   1 << OBD_SECPERM_FS_GETQUOTA, name);
	up_read(&obd_secpol_rwsem);

	return rc;
}
EXPORT_SYMBOL(obd_security_check_getquota);

#include <linux/xattr.h>
#define XATTR_SELINUX_SUFFIX "selinux"
#define XATTR_NAME_SELINUX XATTR_SECURITY_PREFIX XATTR_SELINUX_SUFFIX

int compat_security_validate_transition(char *oldlabel, char *newlabel,
					char *tlabel, umode_t mode);

/**
 * \brief Check inode_setxattr security.
 * \param tcon The task context
 * \param sbcon The superblock context
 * \param icon The inode context
 * \param mode The inode mode
 * \param fname The file name (for audit)
 * \param name The EA name
 * \param value The EA value
 * \param size The EA value size
 * \param capa The task capabilities
 * \param fsuid The task fsuid
 * \param iuid The inode UID
 * \retval 0 success and the operation is permitted
 * \retval -EACCES operation not permitted by the policy
 */
int obd_security_check_setxattr(char *tcon, char *sbcon, char *icon,
				umode_t mode, char *fname,
				void *value, size_t size, char *name,
				__u64 capa, __u32 fsuid, __u32 iuid)
{
	int rc = 0;

	down_read(&obd_secpol_rwsem);

	if (strcmp(name, XATTR_NAME_SELINUX)) {
		if (!strncmp(name, XATTR_SECURITY_PREFIX,
			     sizeof XATTR_SECURITY_PREFIX - 1)) {
			/*if (!strcmp(name, XATTR_NAME_CAPS)) {
				if (!(capa & (1 << CAP_SETFCAP)))
					return -EPERM;
			} else */
			if (!(capa & (1 << CFS_CAP_SYS_ADMIN))) {
				/* A different attribute in the security
				 * namespace. Restrict to administrator. */
				rc = -EPERM;
				goto out;
			}
		}

		rc = obd_security_has_perm(tcon, icon,
					inode_mode_to_security_class(mode),
					1 << OBD_SECPERM_FILE_SETATTR, fname);
		goto out;
	}

	if (!(fsuid == iuid || capa & (1 << CFS_CAP_FOWNER))) {
		rc = -EPERM;
		goto out;
	}

	rc = obd_security_has_perm(tcon, icon, inode_mode_to_security_class(mode),
				   1 << OBD_SECPERM_FILE_RELABELFROM, fname);
	if (rc)
		goto out;

	rc = obd_security_has_perm(tcon, value, inode_mode_to_security_class(mode),
				   1 << OBD_SECPERM_FILE_RELABELTO, fname);
	if (rc)
		goto out;

	rc = compat_security_validate_transition(icon, value, tcon, mode);
	if (rc)
		goto out;

	rc = obd_security_has_perm(value, sbcon, OBD_SECCLASS_FS,
				   1 << OBD_SECPERM_FS_ASSOCIATE, fname);
out:
	up_read(&obd_secpol_rwsem);

	return rc;
}
EXPORT_SYMBOL(obd_security_check_setxattr);

/**
 * \brief Check inode_removexattr security.
 * \param tcon The task context
 * \param icon The inode context
 * \param mode The inode mode
 * \param fname The file name (for audit)
 * \param name The EA name
 * \param capa The task capabilities
 * \retval 0 success and the operation is permitted
 * \retval -EACCES operation not permitted by the policy
 */
int obd_security_check_removexattr(char *tcon, char *icon, umode_t mode,
				   char *fname, char *name, __u64 capa)
{
	int rc;

	if (!strcmp(name, XATTR_NAME_SELINUX))
		return -EACCES;

	if (!strncmp(name, XATTR_SECURITY_PREFIX,
		     sizeof XATTR_SECURITY_PREFIX - 1)) {
//	if (!strcmp(name, XATTR_NAME_CAPS)) {
//			if (!(capa & (1 << CFS_CAP_SETFCAP)))
//				return -EPERM;
//		} else 
		if (!(capa & (1 << CFS_CAP_SYS_ADMIN))) {
			/* A different attribute in the security namespace.
			   Restrict to administrator. */
			return -EPERM;
		}
	}

	down_read(&obd_secpol_rwsem);
	rc = obd_security_has_perm(tcon, icon,
			    inode_mode_to_security_class(mode),
			    1 << OBD_SECPERM_FILE_SETATTR, fname);
	up_read(&obd_secpol_rwsem);

	return rc;
}
EXPORT_SYMBOL(obd_security_check_removexattr);

/**
 * \brief Check inode_getxattr security.
 * \param tcon The task context
 * \param ocon The object context
 * \param mode The object mode
 * \param name The object name (for audit)
 * \retval 0 success and the operation is permitted
 * \retval -EACCES operation not permitted by the policy
 */
int obd_security_check_getxattr(char *tcon, char *ocon, umode_t mode, char *name)
{
	int rc;

	down_read(&obd_secpol_rwsem);
	rc = obd_security_has_perm(tcon, ocon,
				   inode_mode_to_security_class(mode),
				   1 << OBD_SECPERM_FILE_GETATTR, name);
	up_read(&obd_secpol_rwsem);

	return rc;
}
EXPORT_SYMBOL(obd_security_check_getxattr);

/**
 * \brief Check inode_listxattr security.
 * \param tcon The task context
 * \param ocon The object context
 * \param mode The object mode
 * \param name The object name (for audit)
 * \retval 0 success and the operation is permitted
 * \retval -EACCES operation not permitted by the policy
 */
int obd_security_check_listxattr(char *tcon, char *ocon, umode_t mode, char *name)
{
	int rc;

	down_read(&obd_secpol_rwsem);
	rc = obd_security_has_perm(tcon, ocon,
				   inode_mode_to_security_class(mode),
				   1 << OBD_SECPERM_FILE_GETATTR, name);
	up_read(&obd_secpol_rwsem);

	return rc;
}
EXPORT_SYMBOL(obd_security_check_listxattr);

/**
 * \brief Initialize security context for the object
 * \param mcon The mount context
 * \param dcon The directory context
 * \param tcon The task context
 * \param tccon The create context
 * \param mode The new object mode
 * \param value The xattr value for the new object
 * \retval 0 success
 * \retval -ENOMEM not enough memory
 */
int obd_security_init_object(char *mcon, char *dcon, char *tcon, char *tccon,
			     umode_t mode, void **value)
{
	int rc = 0;

	if (mcon != NULL)
		tccon = mcon;

	if (tccon != NULL) {
		*value = kstrdup(tccon, GFP_KERNEL);
		if (*value == NULL)
			rc = -ENOMEM;
	} else {
		down_read(&obd_secpol_rwsem);
		rc = obd_security_transition(tcon, dcon,
					     inode_mode_to_security_class(mode),
					     (char **)value);
		up_read(&obd_secpol_rwsem);
	}

	return rc;
}
EXPORT_SYMBOL(obd_security_init_object);

static int obd_map_classes_and_perms(void)
{
	char name[128];
	int i, j, rc;

	LCONSOLE_INFO("Loading security classes and permissions:\n");

	for (i = OBD_SECCLASS_DIR; i < OBD_SECCLASS_MAX; i++) {
		struct obd_secclass_map_s *class= &obd_secclass_map[i];

		snprintf(name, sizeof(name), "/selinux/class/%s/index", class->name);
		rc = obd_security_file_read_u64(name, &class->policy_class);
		if (rc < 0)
			goto out;

		for (j = 0; class->perm[j].name != NULL; j++) {
			struct obd_secperms_map_s *perm = &class->perm[j];

			snprintf(name, sizeof(name), "/selinux/class/%s/perms/%s",
				 class->name, perm->name);

			rc = obd_security_file_read_u64(name, &perm->policy_perm);
			if (rc < 0)
				goto out;

		}

		CDEBUG(D_CONSOLE, "\tmapped class %s:%llu\n",
		       class->name, class->policy_class);
	}
out:
	return rc;
}

#define SUSER "user_u:user_r:user_t:s0"
#define OUSER "user_u:object_r:user_home_t:s0"
#define SADM  "root:sysadm_r:sysadm_t:s0-s15:c0.c1023"
#define OADM  "system_u:object_r:admin_home_t:s0"

void obd_security_selftest(void)
{
	int rc;
	char *trcon = NULL;

	LCONSOLE_INFO("OBD security self-tests:\n");

	rc = obd_security_has_perm(SUSER, OUSER, OBD_SECCLASS_FILE,
				   1 << OBD_SECPERM_FILE_READ, NULL);
	LCONSOLE_INFO("\t%s -> read -> %s, rc=%d\n", SUSER, OUSER, rc);

	rc = obd_security_has_perm(SADM, OADM, OBD_SECCLASS_FILE,
				   1 << OBD_SECPERM_FILE_READ, NULL);
	LCONSOLE_INFO("\t%s -> read -> %s, rc=%d\n", SADM, OADM, rc);

	rc = obd_security_has_perm(SUSER, OADM, OBD_SECCLASS_FILE,
				   1 << OBD_SECPERM_FILE_READ, NULL);
	LCONSOLE_INFO("\t%s -> read -> %s, rc=%d\n", SUSER, OADM, rc);

	rc = obd_security_transition(SUSER, OUSER, OBD_SECCLASS_FILE, &trcon);
	LCONSOLE_INFO("\t%s -> create -> %s -> %s\n", SUSER, OUSER, trcon);
	if (trcon != NULL)
		kfree(trcon);
}

/* XXX: Unfortunately, security_validate_transition() is not available
 *	in any way different from security_inode_setxattr(). The only
 *	thing we have to do is call SELinux core functions and hope
 *	that in the future we'll get a cleaner way to validate tr.
 */

#define SECCLASS_FILE                                     6
#define SECCLASS_DIR                                      7
#define SECCLASS_FD                                       8
#define SECCLASS_LNK_FILE                                 9
#define SECCLASS_CHR_FILE                                10
#define SECCLASS_BLK_FILE                                11
#define SECCLASS_SOCK_FILE                               12
#define SECCLASS_FIFO_FILE                               13
#define SECCLASS_SOCKET                                  14

static inline u16 compat_inode_mode_to_security_class(umode_t mode)
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

int (*svt)(u32 oldsid, u32 newsid, u32 tasksid, u16 tclass);

int compat_security_find_validate_transition(void *data, const char *name, struct module *m, unsigned long addr)
{
	if (!strcmp("security_validate_transition", name)) {
		svt = (void *)addr;
		LCONSOLE_INFO("found svt @ %lx\n", addr);
		return 1;
	}

	return 0;
}

int compat_security_validate_transition(char *oldlabel, char *newlabel, char *tlabel, umode_t mode)
{
	u32 oldsid, newsid, tasksid;
	int rc;

	rc = security_secctx_to_secid(oldlabel, strlen(oldlabel), &oldsid);
	if (rc < 0)
		return rc;

	rc = security_secctx_to_secid(newlabel, strlen(newlabel), &newsid);
	if (rc < 0)
		return rc;

	rc = security_secctx_to_secid(tlabel, strlen(tlabel), &tasksid);
	if (rc < 0)
		return rc;

	return svt(oldsid, newsid, tasksid, compat_inode_mode_to_security_class(mode));
}

/*
 * Although we can read the information from /proc/self/attr/fscreate,
 * the environment on the client is less controllable than on the server.
 * The concern is that we may not have procfs mounted at /proc sometimes.
 */
int (*sgpa)(struct task_struct *p, char *name, char **value);

int compat_security_find_getprocattr(void *data, const char *name,
				     struct module *m, unsigned long addr)
{
	if (!strcmp("security_getprocattr", name)) {
		sgpa = (void *)addr;
		LCONSOLE_INFO("found sgpa @ %lx\n", addr);
		return 1;
	}

	return 0;
}

int obd_security_get_create_label(char **value)
{
	return sgpa(current, "fscreate", value);
}
EXPORT_SYMBOL(obd_security_get_create_label);

static int obd_security_load_policy(void)
{
	mm_segment_t fs = get_fs();
	int rc;

	obd_security_perm_init();
	obd_security_transition_init();

	/* module is loaded in userspace context, so we need to modify mm limits */
	set_fs(KERNEL_DS);

	rc = obd_security_file_read_u64(SELINUX_OPENPERMS_FILE,
					&obd_security_openperm);
	if (rc < 0)
		goto out;

	rc = obd_security_file_read(SELINUX_FILE_INITCON,
				    obd_security_file_initcon,
				    sizeof(obd_security_file_initcon));
	if (rc < 0)
		goto out;

	rc = obd_map_classes_and_perms();
	if (rc < 0)
		goto out;

	/* Self-test fills out caches, so be careful when returning error */
	obd_security_selftest();

out:
	set_fs(fs);

	return rc;

}

static void obd_security_unload_policy(void)
{
	obd_security_perm_fini();
	obd_security_transition_fini();
}

void obd_security_reload_policy(struct work_struct *unused)
{
	down_write(&obd_secpol_rwsem);
	obd_security_unload_policy();
	obd_security_load_policy();
	up_write(&obd_secpol_rwsem);
}


int obd_security_trigger_reload_policy(u32 seqno)
{
	static DECLARE_WORK(reload_work, obd_security_reload_policy);

	LCONSOLE_INFO("Lustre: reloading security policy\n");
	schedule_work(&reload_work);

	jprobe_return();

	return 0;
}

static struct jprobe obd_security_jp = {
	.entry          = obd_security_trigger_reload_policy,
	.kp.symbol_name = "avc_ss_reset"
};

int obd_security_jp_registered = 0;

int obd_security_init(void)
{
	int rc;

	kallsyms_on_each_symbol(compat_security_find_validate_transition, NULL);
	if (svt == NULL) {
		CERROR("Error: svt not found\n");
		return -ENOENT;
	}

	kallsyms_on_each_symbol(compat_security_find_getprocattr, NULL);
	if (sgpa == NULL) {
		CERROR("Error: sgpa not found\n");
		return -ENOENT;
	}

	rc = obd_security_load_policy();
	if (rc < 0)
		goto out;

	rc = register_jprobe(&obd_security_jp);
	if (rc < 0)
		CERROR("Error: failed to hook cache reload\n");
	else
		obd_security_jp_registered = 1;
out:
	return rc;
}

void obd_security_fini(void)
{
	if (obd_security_jp_registered)
		unregister_jprobe(&obd_security_jp);
	obd_security_unload_policy();
}
