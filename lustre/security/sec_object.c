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
 * GPL HEADER END
 */

/*
 * The Lustre Security Layer.
 *
 * This layer sits between the MDD and the OSD and implements
 * SELinux security checks via libcfs AVC wrappers.
 *
 * Copyright (c) 2013 Xyratex, Inc.
 *
 * Authors:
 * Artem Blagodarenko <artem_blagodarenko@xyratex.com>
 * Andrew Perepechko <andrew_perepechko@xyratex.com>
 *
 */

#define DEBUG_SUBSYSTEM S_LQUOTA

#include "sec_internal.h"

#define INITCON_FS_LABEL "system_u:object_r:fs_t:s0"

static int sec_get_object_label(const struct lu_env *env,
				struct md_object *mo,
				char seclabel[CFS_SID_MAX_LEN])
{
	struct lu_buf buf = { .lb_buf = seclabel, .lb_len = CFS_SID_MAX_LEN };
	int rc;

	ENTRY;

	rc = mo_xattr_get(env, md_object_next(mo), &buf,
			  XATTR_NAME_SECURITY_SELINUX);
	if (rc <= 0) {
		rc = obd_security_file_default_label(seclabel);
		CDEBUG(D_OTHER, "security attrs not found for object, "
				"using default SID %s, rc %d\n",
				seclabel, rc);
	}

	RETURN(0);
}

/**
 * \addtogroup sec
 * @{
 */
static const struct md_object_operations sec_mo_ops;
static const struct md_dir_operations sec_dir_ops;
static const struct lu_object_operations sec_obj_ops;

/**
 * \ingroup sec
 * Allocate security object.
 */
struct lu_object *sec_object_alloc(const struct lu_env *env,
				   const struct lu_object_header *loh,
				   struct lu_device *ld)
{
	struct lu_object *lo = NULL;
	struct sec_object *clo;
	ENTRY;

	OBD_ALLOC_PTR(clo);
	if (clo != NULL) {
		lo = &clo->sec_obj.mo_lu;
		lu_object_init(lo, NULL, ld);
		clo->sec_obj.mo_ops = &sec_mo_ops;
		clo->sec_obj.mo_dir_ops = &sec_dir_ops;
		lo->lo_ops = &sec_obj_ops;
	}
	RETURN(lo);
}


/**
 * Get local child device.
 */
static struct lu_device *sec_child_dev(struct sec_device *d)
{
	return &d->sec_child->md_lu_dev;
}

/**
 * Free sec_object.
 */
static void sec_object_free(const struct lu_env *env, struct lu_object *lo)
{
	struct sec_object *clo = lu2sec_obj(lo);
	lu_object_fini(lo);
	OBD_FREE_PTR(clo);
}

/**
 * Initialize sec_object.
 */
static int sec_object_init(const struct lu_env *env, struct lu_object *lo,
			   const struct lu_object_conf *unused)
{
	struct sec_device *cd = lu2sec_dev(lo->lo_dev);
	struct lu_device *c_dev;
	struct lu_object *c_obj;
	int rc;

	ENTRY;

	c_dev = sec_child_dev(cd);
	if (c_dev == NULL) {
		rc = -ENOENT;
	} else {
		c_obj = c_dev->ld_ops->ldo_object_alloc(env,
							lo->lo_header,
							c_dev);
		if (c_obj != NULL) {
			lu_object_add(lo, c_obj);
			rc = 0;
		} else {
			rc = -ENOMEM;
		}
	}

	RETURN(rc);
}

static int sec_object_print(const struct lu_env *env, void *cookie,
			    lu_printer_t p, const struct lu_object *lo)
{
	return 0;
}

static const struct lu_object_operations sec_obj_ops = {
	.loo_object_init = sec_object_init,
	.loo_object_free = sec_object_free,
	.loo_object_print = sec_object_print
};

static int sec_object_create(const struct lu_env *env,
			     struct md_object *mo,
			     const struct md_op_spec *spec,
			     struct md_attr *attr)
{
	int rc;
	ENTRY;
	rc = mo_object_create(env, md_object_next(mo), spec, attr);
	RETURN(rc);
}

static int sec_permission(const struct lu_env *env,
			  struct md_object *p, struct md_object *c,
			  struct md_attr *attr, int mask)
{
	struct lu_ucred *uc = lu_ucred(env);
	int rc;
	char olabel[CFS_SID_MAX_LEN];
	char name[30];
	struct md_attr mda;

	ENTRY;

	snprintf(name, sizeof(name), DFID, PFID(sec2fid(md2sec_obj(c))));

	mda.ma_need = MA_INODE;
	mda.ma_valid = 0;
	rc = mo_attr_get(env, md_object_next(c), &mda);
	if (rc < 0)
		RETURN(rc);

	rc = sec_get_object_label(env, c, olabel);
	if (rc) {
		CERROR("failed to get object SID for %s\n", name);
		RETURN(rc);
	}

	rc = obd_security_check_permission(uc->uc_seclabel, olabel, mda.ma_attr.la_mode,
					   mask, name);
	if (rc) {
		CDEBUG(D_OTHER, "security_permission failed for %s, tlabel %s, "
				"olabel %s, rc %d\n", name, uc->uc_seclabel, olabel, rc);
		RETURN(rc);
	}

	rc = mo_permission(env, md_object_next(p), md_object_next(c),
			   attr, mask);
	RETURN(rc);
}

static int sec_attr_get(const struct lu_env *env, struct md_object *mo,
			struct md_attr *attr)
{
	struct lu_ucred *uc = lu_ucred(env);
	int rc;
	char olabel[CFS_SID_MAX_LEN];
	char name[30];
	struct md_attr mda;

	ENTRY;

	if (uc->uc_confined_op != UC_CONFINED_GETATTR)
		goto skip_checks;

	snprintf(name, sizeof(name), DFID, PFID(sec2fid(md2sec_obj(mo))));

	mda.ma_need = MA_INODE;
	mda.ma_valid = 0;
	rc = mo_attr_get(env, md_object_next(mo), &mda);
	if (rc < 0)
		RETURN(rc);

	rc = sec_get_object_label(env, mo, olabel);
	if (rc) {
		CERROR("failed to get object SID for %s, rc %d\n", name, rc);
		RETURN(rc);
	}

	rc = obd_security_check_getattr(uc->uc_seclabel, olabel, mda.ma_attr.la_mode, name);
	if (rc) {
		CDEBUG(D_OTHER, "security_getattr failed for %s, tlabel %s, "
				"olabel %s, rc %d\n", name, uc->uc_seclabel, olabel, rc);
		RETURN(rc);
	}

skip_checks:
	rc = mo_attr_get(env, md_object_next(mo), attr);
	RETURN(rc);
}

static int sec_attr_set(const struct lu_env *env, struct md_object *mo,
			const struct md_attr *attr)
{
	struct lu_ucred *uc = lu_ucred(env);
	int rc;
	char olabel[CFS_SID_MAX_LEN];
	char name[30];
	struct iattr iattr;
	struct md_attr mda;
	ENTRY;

	/* XXX: MDS_CLOSE updates atime */
	if (uc == NULL || uc->uc_seclabel[0] == '\0')
		goto skip_checks;

	snprintf(name, sizeof(name), DFID, PFID(sec2fid(md2sec_obj(mo))));

	mda.ma_need = MA_INODE;
	mda.ma_valid = 0;
	rc = mo_attr_get(env, md_object_next(mo), &mda);
	if (rc < 0)
		RETURN(rc);

	rc = sec_get_object_label(env, mo, olabel);
	if (rc) {
		CERROR("failed to get object SID for %s, rc %d\n", name, rc);
		RETURN(rc);
	}

	iattr.ia_valid = attr->ma_valid;
	rc = obd_security_check_setattr(uc->uc_seclabel, olabel, mda.ma_attr.la_mode,
				        &iattr, name);
	if (rc) {
		CDEBUG(D_OTHER, "security_setattr failed for %s, tlabel %s, "
				"olabel %s, rc %d\n", name, uc->uc_seclabel, olabel, rc);
		RETURN(rc);
	}

skip_checks:
	rc = mo_attr_set(env, md_object_next(mo), attr);
	RETURN(rc);
}

static int sec_xattr_get(const struct lu_env *env, struct md_object *mo,
			 struct lu_buf *buf, const char *name)
{
	struct lu_ucred *uc = lu_ucred(env);
	int rc;
	char olabel[CFS_SID_MAX_LEN];
	char file_name[30];
	struct md_attr mda;
	ENTRY;

	/* XXX: uc can be NULL if running mdt_lvbo_fill */
	/* XXX: MDS_CLOSE updates atime */
	if (uc == NULL || uc->uc_seclabel[0] == '\0')
		goto skip_checks;

	/* XXX: not right, but doinit_with_dentry should succeed on the client */
	if (name != NULL && !strcmp(name, "security.selinux"))
		goto skip_checks;

	snprintf(file_name, sizeof(file_name), DFID,
		 PFID(sec2fid(md2sec_obj(mo))));

	mda.ma_need = MA_INODE;
	mda.ma_valid = 0;
	rc = mo_attr_get(env, md_object_next(mo), &mda);
	if (rc < 0)
		RETURN(rc);

	rc = sec_get_object_label(env, mo, olabel);
	if (rc) {
		CERROR("failed to get object SID for %s, rc %d\n",
		       file_name, rc);
		RETURN(rc);
	}

	rc = obd_security_check_getxattr(uc->uc_seclabel, olabel,
			  mda.ma_attr.la_mode, (char *)file_name);
	if (rc) {
		CDEBUG(D_OTHER, "security_getxattr failed for %s, tlabel %s, "
				"olabel %s, rc %d\n", name, uc->uc_seclabel, olabel, rc);
		RETURN(rc);
	}

skip_checks:
	rc = mo_xattr_get(env, md_object_next(mo), buf, name);

	RETURN(rc);
}

static int sec_readlink(const struct lu_env *env, struct md_object *mo,
			struct lu_buf *buf)
{
	struct lu_ucred *uc = lu_ucred(env);
	char name[30];
	char ilabel[CFS_SID_MAX_LEN];
	int rc;
	ENTRY;

	snprintf(name, sizeof(name), DFID, PFID(sec2fid(md2sec_obj(mo))));

	rc = sec_get_object_label(env, mo, ilabel);
	if (rc) {
		CERROR("failed to get object SID for %s, rc %d\n", name, rc);
		RETURN(rc);
	}

	rc = obd_security_check_readlink(uc->uc_seclabel, ilabel, S_IFLNK, name);
	if (rc < 0) {
		CDEBUG(D_OTHER, "security_readlink failed for %s, tlabel %s, "
				"ilabel %s, rc %d\n", name, uc->uc_seclabel, ilabel, rc);
		RETURN(rc);
	}

	rc = mo_readlink(env, md_object_next(mo), buf);
	RETURN(rc);
}

static int sec_changelog(const struct lu_env *env,
			 enum changelog_rec_type type, int flags,
			 struct md_object *mo)
{
	int rc;
	ENTRY;
	rc = mo_changelog(env, type, flags, md_object_next(mo));
	RETURN(rc);
}

static int sec_xattr_list(const struct lu_env *env, struct md_object *mo,
			  struct lu_buf *buf)
{
	struct lu_ucred *uc = lu_ucred(env);
	int rc;
	char olabel[CFS_SID_MAX_LEN];
	char file_name[30];
	struct md_attr mda;
	ENTRY;

	snprintf(file_name, sizeof(file_name),
		 DFID, PFID(sec2fid(md2sec_obj(mo))));

	mda.ma_need = MA_INODE;
	mda.ma_valid = 0;
	rc = mo_attr_get(env, md_object_next(mo), &mda);
	if (rc < 0)
		RETURN(rc);

	rc = sec_get_object_label(env, mo, olabel);
	if (rc) {
		CERROR("failed to get object SID for %s, rc %d\n",
		       file_name, rc);
		RETURN(rc);
	}

	rc = obd_security_check_listxattr(uc->uc_seclabel, olabel,
			  mda.ma_attr.la_mode, (char *)file_name);
	if (rc) {
		CDEBUG(D_OTHER, "security_listxattr failed for %s, tlabel %s, "
				"ilabel %s, rc %d\n", file_name, uc->uc_seclabel, olabel,
				rc);
		RETURN(rc);
	}

	rc = mo_xattr_list(env, md_object_next(mo), buf);
	RETURN(rc);
}

static int sec_xattr_set(const struct lu_env *env, struct md_object *mo,
			 const struct lu_buf *buf, const char *name,
			 int fl)
{
	struct lu_ucred *uc = lu_ucred(env);
	int rc;
	char ilabel[CFS_SID_MAX_LEN];
	char file_name[30];
	struct md_attr mda;
	ENTRY;

	snprintf(file_name, sizeof(file_name),
		 DFID, PFID(sec2fid(md2sec_obj(mo))));

	mda.ma_need = MA_INODE;
	mda.ma_valid = 0;
	rc = mo_attr_get(env, md_object_next(mo), &mda);
	if (rc < 0)
		RETURN(rc);

	rc = sec_get_object_label(env, mo, ilabel);
	if (rc) {
		CERROR("failed to get object SID for %s, rc %d\n",
		       file_name, rc);
		RETURN(rc);
	}

	rc = obd_security_check_setxattr(uc->uc_seclabel, INITCON_FS_LABEL, ilabel,
			  mda.ma_attr.la_mode, file_name,
			  buf->lb_buf, buf->lb_len, (char *)name,
			  uc->uc_cap, uc->uc_fsuid, mda.ma_attr.la_uid);
	if (rc) {
		CDEBUG(D_OTHER, "security_setxattr failed for %s, tlabel %s, "
				"ilabel %s, rc %d\n", file_name, uc->uc_seclabel, ilabel,
				rc);
		RETURN(rc);
	}

	rc = mo_xattr_set(env, md_object_next(mo), buf, name, fl);
	RETURN(rc);
}

static int sec_xattr_del(const struct lu_env *env, struct md_object *mo,
			 const char *name)
{
	struct lu_ucred *uc = lu_ucred(env);
	int rc;
	char ilabel[CFS_SID_MAX_LEN];
	char file_name[30];
	struct md_attr mda;
	ENTRY;

	snprintf(file_name, sizeof(file_name),
		 DFID, PFID(sec2fid(md2sec_obj(mo))));

	mda.ma_need = MA_INODE;
	mda.ma_valid = 0;
	rc = mo_attr_get(env, md_object_next(mo), &mda);
	if (rc < 0)
		RETURN(rc);

	rc = sec_get_object_label(env, mo, ilabel);
	if (rc) {
		CERROR("failed to get object SID for %s, rc %d\n",
		       file_name, rc);
		RETURN(rc);
	}

	rc = obd_security_check_removexattr(uc->uc_seclabel, ilabel, mda.ma_attr.la_mode,
				      file_name, (char *)name, uc->uc_cap);
	if (rc) {
		CDEBUG(D_OTHER, "security_removexattr failed for %s, tlabel %s, "
				"ilabel %s, rc %d\n", file_name, uc->uc_seclabel, ilabel,
				rc);
		RETURN(rc);
	}


	rc = mo_xattr_del(env, md_object_next(mo), name);
	RETURN(rc);
}

/**
 * swap layouts between 2 lustre objects
 */
static int sec_swap_layouts(const struct lu_env *env, struct md_object *obj1,
			    struct md_object *obj2, __u64 flags)
{
	int rc;
	ENTRY;
	rc = mo_swap_layouts(env, md_object_next(obj1), md_object_next(obj2),
			     flags);
	RETURN(rc);
}

static int sec_ref_add(const struct lu_env *env, struct md_object *mo,
		       const struct md_attr *ma)
{
	int rc;
	ENTRY;
	rc = mo_ref_add(env, md_object_next(mo), ma);
	RETURN(rc);
}

static int sec_ref_del(const struct lu_env *env, struct md_object *mo,
		       struct md_attr *ma)
{
	int rc;
	ENTRY;
	rc = mo_ref_del(env, md_object_next(mo), ma);
	RETURN(rc);
}

static int sec_open(const struct lu_env *env, struct md_object *mo, int flags)
{
	struct lu_ucred *uc = lu_ucred(env);
	int rc;
	char olabel[CFS_SID_MAX_LEN];
	char file_name[30];
	struct md_attr mda;

	ENTRY;

	snprintf(file_name, sizeof(file_name),
		 DFID, PFID(sec2fid(md2sec_obj(mo))));

	mda.ma_need = MA_INODE;
	mda.ma_valid = 0;
	rc = mo_attr_get(env, md_object_next(mo), &mda);
	if (rc < 0) {
		CERROR("failed to get attrs for %s\n", file_name);
		RETURN(rc);
	}

	rc = sec_get_object_label(env, mo, olabel);
	if (rc) {
		CERROR("failed to get object SID for %s, rc %d\n",
		       file_name, rc);
		RETURN(rc);
	}

	rc = obd_security_check_open(uc->uc_seclabel, olabel, mda.ma_attr.la_mode,
				     flags & (FMODE_READ | FMODE_WRITE),
				     (flags & MDS_OPEN_APPEND) ? O_APPEND : 0,
				     file_name);
	if (rc) {
		CDEBUG(D_OTHER, "security_open failed for %s, tlabel %s, "
				"olabel %s, rc %d\n", file_name, uc->uc_seclabel,
				olabel, rc);
		RETURN(rc);
	}
	rc = mo_open(env, md_object_next(mo), flags);
	RETURN(rc);
}

static int sec_close(const struct lu_env *env, struct md_object *mo,
		     struct md_attr *ma, int mode)
{
	int rc;
	ENTRY;
	rc = mo_close(env, md_object_next(mo), ma, mode);
	RETURN(rc);
}

static int sec_readpage(const struct lu_env *env, struct md_object *mo,
			const struct lu_rdpg *rdpg)
{
	struct lu_ucred *uc = lu_ucred(env);
	int rc;
	char dlabel[CFS_SID_MAX_LEN];
	char name[30];

	ENTRY;

	snprintf(name, sizeof(name), DFID, PFID(sec2fid(md2sec_obj(mo))));

	rc = sec_get_object_label(env, mo, dlabel);
	if (rc) {
		CERROR("failed to get dir SID for %s\n", name);
		RETURN(rc);
	}

	rc = obd_security_check_permission(uc->uc_seclabel, dlabel, S_IFDIR, MAY_READ, name);
	if (rc) {
		CDEBUG(D_OTHER, "security_permission failed for %s, tlabel %s, "
				"dlabel %s, rc %d\n", name, uc->uc_seclabel, dlabel, rc);
		RETURN(rc);
	}

	rc = mo_readpage(env, md_object_next(mo), rdpg);
	RETURN(rc);
}

static int sec_capa_get(const struct lu_env *env, struct md_object *mo,
			struct lustre_capa *capa, int renewal)
{
	int rc;
	ENTRY;
	rc = mo_capa_get(env, md_object_next(mo), capa, renewal);
	RETURN(rc);
}

static int sec_object_sync(const struct lu_env *env, struct md_object *mo)
{
	int rc;
	ENTRY;
	rc = mo_object_sync(env, md_object_next(mo));
	RETURN(rc);
}

static int sec_file_lock(const struct lu_env *env, struct md_object *mo,
			 struct lov_mds_md *lmm,
			 struct ldlm_extent *extent,
			 struct lustre_handle *lockh)
{
	struct lu_ucred *uc = lu_ucred(env);
	int rc;
	char olabel[CFS_SID_MAX_LEN];
	char file_name[30];
	struct md_attr mda;
	ENTRY;

	snprintf(file_name, sizeof(file_name),
		 DFID, PFID(sec2fid(md2sec_obj(mo))));

	mda.ma_need = MA_INODE;
	mda.ma_valid = 0;
	rc = mo_attr_get(env, md_object_next(mo), &mda);
	if (rc < 0)
		RETURN(rc);

	rc = sec_get_object_label(env, mo, olabel);
	if (rc)
		RETURN(rc);

	/* TODO: add fsid */
	rc = obd_security_check_lock(uc->uc_seclabel, olabel, 0,
				     mda.ma_attr.la_mode, file_name);
	if (rc)
		RETURN(rc);

	rc = mo_file_lock(env, md_object_next(mo), lmm, extent, lockh);
	RETURN(rc);
	return -EREMOTE;
}

static int sec_file_unlock(const struct lu_env *env, struct md_object *mo,
			   struct lov_mds_md *lmm,
			   struct lustre_handle *lockh)
{
	int rc;
	ENTRY;
	rc = mo_file_unlock(env, md_object_next(mo), lmm, lockh);
	RETURN(rc);
}

/** Set of md_object_operations for sec. */
static const struct md_object_operations sec_mo_ops = {
	.moo_permission = sec_permission,
	.moo_attr_get = sec_attr_get,
	.moo_attr_set = sec_attr_set,
	.moo_xattr_get = sec_xattr_get,
	.moo_xattr_set = sec_xattr_set,
	.moo_xattr_list = sec_xattr_list,
	.moo_xattr_del = sec_xattr_del,
	.moo_swap_layouts = sec_swap_layouts,
	.moo_object_create = sec_object_create,
	.moo_ref_add = sec_ref_add,
	.moo_ref_del = sec_ref_del,
	.moo_open = sec_open,
	.moo_close = sec_close,
	.moo_readpage = sec_readpage,
	.moo_readlink = sec_readlink,
	.moo_changelog = sec_changelog,
	.moo_capa_get = sec_capa_get,
	.moo_object_sync = sec_object_sync,
	.moo_file_lock = sec_file_lock,
	.moo_file_unlock = sec_file_unlock,
};

static int sec_lookup(const struct lu_env *env, struct md_object *mo_p,
		      const struct lu_name *lname, struct lu_fid *lf,
		      struct md_op_spec *spec)
{
	int rc;
	ENTRY;

	rc = mdo_lookup(env, md_object_next(mo_p), lname, lf, spec);
	RETURN(rc);
}

/** Return lock mode. */
static mdl_mode_t sec_lock_mode(const struct lu_env *env,
				struct md_object *mo, mdl_mode_t lm)
{
	int rc = MDL_MINMODE;
	ENTRY;


	RETURN(rc);
}

/**
 * Create operation for sec.
 * Remote object creation and local name insert.
 *
 * \param mo_p Parent directory. Local object.
 * \param lchild_name name of file to create.
 * \param mo_c Child object. It has no real inode yet.
 * \param spec creation specification.
 * \param ma child object attributes.
 */
static int sec_create(const struct lu_env *env, struct md_object *mo_p,
		      const struct lu_name *lchild_name,
		      struct md_object *mo_c, struct md_op_spec *spec,
		      struct md_attr *ma)
{
	int rc;
	struct lu_ucred *uc = lu_ucred(env);
	struct lu_buf xattr_buf;
	char label[CFS_SID_MAX_LEN];
	void * attr_value;
	char name[30], dir_name[30];
	ENTRY;

	snprintf(name, sizeof(name), DFID, PFID(sec2fid(md2sec_obj(mo_c))));
	snprintf(dir_name, sizeof(dir_name),
		 DFID, PFID(sec2fid(md2sec_obj(mo_p))));

	rc = sec_get_object_label(env, mo_p, label);
	if (rc < 0) {
		CERROR("failed to get object SID for %s, rc %d\n",
		       dir_name, rc);
		RETURN(rc);
	}

	/* Note that the first argument is not uc->uc_sbsid,
	 * but rather mntpoint_sid */
	rc = obd_security_init_object(/*0, sid, uc->uc_sid,
				      uc->uc_csid */ NULL, label, uc->uc_seclabel, NULL, ma->ma_attr.la_mode,
				      &attr_value);
	if(rc) {
		CERROR("security_init failed for a new object in directory %s, "
		       "tlabel %s, rc %d\n", dir_name, uc->uc_seclabel, rc);
		RETURN(rc);
	}

//	rc = cfs_string_to_sid_default(&new_sid, uc->uc_defsid,
//				       attr_value, attr_len - 1);
//	if(rc) {
//		CERROR("failed to convert initial context %s to SID, rc %d\n",
//		       (char *)attr_value, rc);
//		RETURN(rc);
//	}

	rc = obd_security_check_create(uc->uc_seclabel /* uc->uc_sid */, NULL /* uc->uc_csid */, label /* sid */, INITCON_FS_LABEL /* uc->uc_sbsid */,
				       ma->ma_attr.la_mode, name);
	if (rc < 0) {
		CDEBUG(D_OTHER, "security_create failed for  %s, tlabel %s, "
				"rc %d\n", name, uc->uc_seclabel, rc);
		RETURN(rc);
	}

	rc = mdo_create(env, md_object_next(mo_p), lchild_name,
			md_object_next(mo_c), spec, ma);
	if (rc)
		RETURN(rc);

	xattr_buf.lb_buf = attr_value;
	xattr_buf.lb_len = strlen(attr_value) + 1;
	rc = mo_xattr_set(env, md_object_next(mo_c), &xattr_buf,
			  XATTR_NAME_SECURITY_SELINUX, LU_XATTR_INTERNAL);
	if (rc) {
		CERROR("failed to save security xattr for %s\n", name);
		RETURN(rc);
	}

	EXIT;
	return rc;
}

/**
 * Call mdo_create_data() on next layer.
 *
 * This function is called as part of create or open(O_CREAT) without
 * O_LOV_DELAY_CREATE. Security checks are handled by sec_create(),
 * so just leave this void.
 */
static int sec_create_data(const struct lu_env *env, struct md_object *p,
			   struct md_object *o,
			   const struct md_op_spec *spec,
			   struct md_attr *ma)
{
	int rc;
	ENTRY;
	rc = mdo_create_data(env, md_object_next(p), md_object_next(o),
			     spec, ma);
	RETURN(rc);
}

/**
 * Link operations for sec.
 *
 * \param mo_p parent directory. It is local.
 * \param mo_s source object to link. It is remote.
 * \param lname Name of link file.
 * \param ma object attributes.
 */
static int sec_link(const struct lu_env *env, struct md_object *mo_p,
		    struct md_object *mo_s, const struct lu_name *lname,
		    struct md_attr *ma)
{
	struct lu_ucred *uc = lu_ucred(env);
	char dlabel[CFS_SID_MAX_LEN], ilabel[CFS_SID_MAX_LEN];
	struct md_attr mda;
	int rc;
	char pname[30], sname[30];
	ENTRY;

	snprintf(pname, sizeof(pname), DFID, PFID(sec2fid(md2sec_obj(mo_p))));
	snprintf(sname, sizeof(sname), DFID, PFID(sec2fid(md2sec_obj(mo_s))));

	rc = sec_get_object_label(env, mo_p, dlabel);
	if (rc < 0) {
		CERROR("failed to get object SID for parent dir %s, rc %d\n",
		       pname, rc);
		RETURN(rc);
	}
	rc = sec_get_object_label(env, mo_s, ilabel);
	if (rc < 0) {
		CERROR("failed to get object SID for source %s, rc %d\n",
		       sname, rc);
		RETURN(rc);
	}

	mda.ma_need = MA_INODE;
	mda.ma_valid = 0;
	rc = mo_attr_get(env, md_object_next(mo_s), &mda);
	if (rc < 0) {
		CERROR("failed to get attrs for %s\n", sname);
		RETURN(rc);
	}

	CDEBUG(D_OTHER, "sec_link: tlabel=%s dlabel=%s ilabel=%s mode=%x, name=%s\n",
	       uc->uc_seclabel, dlabel, ilabel, mda.ma_attr.la_mode, lname->ln_name);

	/* XXX: what should really go to audit? */
	rc = obd_security_check_link(uc->uc_seclabel /* uc->uc_sid */, dlabel /* dsid */, ilabel /* isid */,
			       mda.ma_attr.la_mode, pname);
	if (rc < 0) {
		CDEBUG(D_OTHER, "security_link failed for dir %s, tlabel %s, "
				"rc %d\n", pname, uc->uc_seclabel, rc);
		RETURN(rc);
	}

	rc = mdo_link(env, md_object_next(mo_p), md_object_next(mo_s),
		      lname, ma);
	RETURN(rc);
}

static int sec_unlink(const struct lu_env *env, struct md_object *mo_p,
		      struct md_object *mo_c, const struct lu_name *lname,
		      struct md_attr *ma, int no_name)
{
	struct lu_ucred *uc = lu_ucred(env);
	char dlabel[CFS_SID_MAX_LEN], ilabel[CFS_SID_MAX_LEN];
	struct md_attr mda;
	int rc;
	char pname[30], cname[30];
	ENTRY;

	snprintf(pname, sizeof(pname), DFID, PFID(sec2fid(md2sec_obj(mo_p))));
	snprintf(cname, sizeof(cname), DFID, PFID(sec2fid(md2sec_obj(mo_c))));

	rc = sec_get_object_label(env, mo_p, dlabel);
	if (rc < 0) {
		CERROR("failed to get object SID for parent dir %s, rc %d\n",
		       pname, rc);
		RETURN(rc);
	}

	rc = sec_get_object_label(env, mo_c, ilabel);
	if (rc < 0) {
		CERROR("failed to get object SID for object %s, rc %d\n",
		       cname, rc);
		RETURN(rc);
	}

	mda.ma_need = MA_INODE;
	mda.ma_valid = 0;
	rc = mo_attr_get(env, md_object_next(mo_c), &mda);
	if (rc < 0) {
		CERROR("failed to get attrs for %s\n", cname);
		RETURN(rc);
	}

	CDEBUG(D_OTHER, "sec_unlink: tsid=%s dsid=%s isid=%s mode=%x, name=%s\n",
	       uc->uc_seclabel, dlabel, ilabel, mda.ma_attr.la_mode, cname);

	rc = obd_security_check_unlink(uc->uc_seclabel, dlabel, ilabel,
				       mda.ma_attr.la_mode, cname);
	if (rc < 0) {
		CDEBUG(D_OTHER, "security_unlink failed for dir %s, object %s,"
				" tlabel %s, rc %d\n", pname, cname, uc->uc_seclabel,
				rc);
		RETURN(rc);
	}

	rc = mdo_unlink(env, md_object_next(mo_p), md_object_next(mo_c),
			lname, ma, no_name);

	RETURN(rc);
}

/**
 * Rename operation for sec.
 *
 * \param mo_po Old parent object.
 * \param mo_pn New parent object.
 * \param lf FID of object to rename.
 * \param ls_name Source file name.
 * \param mo_t target object. Should be NULL here.
 * \param lt_name Name of target file.
 * \param ma object attributes.
 */
static int sec_rename(const struct lu_env *env,
		      struct md_object *mo_po, struct md_object *mo_pn,
		      const struct lu_fid *lf,
		      const struct lu_name *ls_name,
		      struct md_object *mo_t,
		      const struct lu_name *lt_name, struct md_attr *ma)
{
	int rc;
	char old_dlabel[CFS_SID_MAX_LEN], old_ilabel[CFS_SID_MAX_LEN], new_dlabel[CFS_SID_MAX_LEN], new_ilabel[CFS_SID_MAX_LEN];
	struct lu_ucred *uc = lu_ucred(env);
	struct md_object *mo_lf;
	struct md_attr mda;
	char fname[30], poname[30], pnname[30];
	bool same_dirs = false;
	ENTRY;

	if (lu_object_fid(&mo_po->mo_lu) == lu_object_fid(&mo_pn->mo_lu))
		same_dirs = true;

	mo_lf = mo_object_find_slice(env, mo_po, lf);
	if (IS_ERR(mo_lf))
		RETURN(PTR_ERR(mo_lf));

	snprintf(fname, sizeof(fname), DFID, PFID(sec2fid(md2sec_obj(mo_lf))));
	snprintf(poname, sizeof(poname),
		 DFID, PFID(sec2fid(md2sec_obj(mo_po))));
	snprintf(pnname, sizeof(pnname),
		 DFID, PFID(sec2fid(md2sec_obj(mo_pn))));

	sec_get_object_label(env, mo_po, old_dlabel);
	sec_get_object_label(env, mo_pn, new_dlabel);
	sec_get_object_label(env, mo_lf, old_ilabel);

	mda.ma_need = MA_INODE;
	mda.ma_valid = 0;
	rc = mo_attr_get(env, md_object_next(mo_lf), &mda);
	if (rc < 0) {
		CERROR("failed to get attrs for %s\n", fname);
		GOTO(out, rc);
	}

	if (mo_t)
		sec_get_object_label(env, mo_t, new_ilabel);

	/* XXX: what names should be used for rename? */
	rc = obd_security_check_rename(uc->uc_seclabel, fname, fname,
				 old_dlabel, old_ilabel,
				 new_dlabel, new_ilabel,
				 mda.ma_attr.la_mode, mda.ma_attr.la_mode,
				 same_dirs, !!mo_t);
	if (rc < 0) {
		CDEBUG(D_OTHER, "security_rename failed for olddir %s, "
				"newdir %s, object %s, tsid %s, rc %d\n",
				poname, pnname,
				fname, uc->uc_seclabel, rc);
		GOTO(out, rc);
	}

	/* local rename, mo_t can be NULL */
	rc = mdo_rename(env, md_object_next(mo_po),
			md_object_next(mo_pn), lf, ls_name,
			md_object_next(mo_t), lt_name, ma);

	lu_object_put(env, &mo_lf->mo_lu);
	RETURN(rc);
out:
	lu_object_put(env, &mo_lf->mo_lu);
	return rc;
}

/**
 * Part of cross-ref rename().
 * Used to insert new name in new parent and unlink target.
 *
 * DNE(?)-related, not interesting for security checks
 */
static int sec_rename_tgt(const struct lu_env *env,
			  struct md_object *mo_p, struct md_object *mo_t,
			  const struct lu_fid *lf,
			  const struct lu_name *lname, struct md_attr *ma)
{
	int rc;
	ENTRY;

	rc = mdo_rename_tgt(env, md_object_next(mo_p),
			    md_object_next(mo_t), lf, lname, ma);
	RETURN(rc);
}

/**
 * \ingroup cmm
 * Check two fids are not subdirectories.
 */
static int sec_is_subdir(const struct lu_env *env, struct md_object *mo,
			 const struct lu_fid *fid, struct lu_fid *sfid)
{
	int rc;
	ENTRY;

	rc = mdo_is_subdir(env, md_object_next(mo), fid, sfid);
	RETURN(rc);
}

/**
 * Name insert only operation.
 * used only in case of rename_tgt() when target doesn't exist.
 *
 * DNE(?)-related, not interesting for security checks
 */
static int sec_name_insert(const struct lu_env *env, struct md_object *p,
			   const struct lu_name *lname,
			   const struct lu_fid *lf,
			   const struct md_attr *ma)
{
	int rc;
	ENTRY;

	rc = mdo_name_insert(env, md_object_next(p), lname, lf, ma);

	RETURN(rc);
}

/** @} */
/**
 * The md_dir_operations for security layer.
 */
static const struct md_dir_operations sec_dir_ops = {
	.mdo_is_subdir = sec_is_subdir,
	.mdo_lookup = sec_lookup,
	.mdo_lock_mode = sec_lock_mode,
	.mdo_create = sec_create,
	.mdo_create_data = sec_create_data,
	.mdo_rename = sec_rename,
	.mdo_link = sec_link,
	.mdo_unlink = sec_unlink,
	.mdo_name_insert = sec_name_insert,
	.mdo_rename_tgt = sec_rename_tgt
};

/** @} */
