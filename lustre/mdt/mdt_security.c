#include "mdt_internal.h"
#include <lustre_security.h>

#define INITCON_FS_LABEL "system_u:object_r:fs_t:s0"

static int mdt_sec_get_object_label(const struct lu_env *env,
				    struct mdt_object *mdo,
				    char seclabel[CFS_SID_MAX_LEN])
{
	struct lu_buf buf = { .lb_buf = seclabel, .lb_len = CFS_SID_MAX_LEN };
	int rc;

	ENTRY;

	rc = mo_xattr_get(env, mdt_object_child(mdo), &buf,
			  XATTR_NAME_SECURITY_SELINUX);
	if (rc <= 0) {
		rc = obd_security_file_default_label(seclabel);
		CDEBUG(D_OTHER, "security attrs not found for object, "
				"using default SID %s, rc %d\n",
				seclabel, rc);
	}

	RETURN(0);
}

int mdt_sec_attr_get(const struct lu_env *env, struct mdt_object *mdo)
{
	struct lu_ucred *uc = lu_ucred(env);
	char olabel[CFS_SID_MAX_LEN];
	char name[30];
	struct md_attr mda;
	int rc;

	ENTRY;

	snprintf(name, sizeof(name), DFID, PFID(mdt_object_fid(mdo)));

	mda.ma_need = MA_INODE;
	mda.ma_valid = 0;
	rc = mo_attr_get(env, mdt_object_child(mdo), &mda);
	if (rc < 0)
		RETURN(rc);

	rc = mdt_sec_get_object_label(env, mdo, olabel);
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

	RETURN(rc);
}

int mdt_sec_xattr_get(const struct lu_env *env, struct mdt_object *mdo,
		      struct lu_buf *buf, const char *name)
{
	struct lu_ucred *uc = lu_ucred(env);
	int rc;
	char olabel[CFS_SID_MAX_LEN];
	char file_name[30];
	struct md_attr mda;
	ENTRY;

	/* XXX: not right, but doinit_with_dentry should succeed on the client */
	if (name != NULL && !strcmp(name, "security.selinux"))
		goto skip_checks;

	snprintf(file_name, sizeof(file_name), DFID,
		 PFID(mdt_object_fid(mdo)));

	mda.ma_need = MA_INODE;
	mda.ma_valid = 0;
	rc = mo_attr_get(env, mdt_object_child(mdo), &mda);
	if (rc < 0)
		RETURN(rc);

	rc = mdt_sec_get_object_label(env, mdo, olabel);
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

	RETURN(rc);
}

int mdt_sec_mount(const struct lu_env *env, char *name)
{
	struct lu_ucred *uc = lu_ucred(env);
	int rc;

	rc = obd_security_check_mount(uc->uc_seclabel, INITCON_FS_LABEL, name);

	return rc;
}
