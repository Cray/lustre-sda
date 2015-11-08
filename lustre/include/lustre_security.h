#ifndef __LUSTRE_SECURITY_H__
#define __LUSTRE_SECURITY_H__
int obd_security_check_open(char *tcon, char *ocon, umode_t mode,
			    fmode_t fmode, unsigned fflags, char *name);
int obd_security_check_permission(char *tcon, char *ocon, int mode,
				  int mask, char *name);
int obd_security_check_setattr(char *tcon, char *ocon, umode_t mode,
			       struct iattr *iattr, char *name);
int obd_security_check_getattr(char *tcon, char *ocon, umode_t mode, char *name);
int obd_security_check_create(char *tcon, char *tccon, char *dcon,
			      char *sbcon, umode_t mode, const char *name);
int obd_security_check_lock(char *tcon, char *ocon, char *fcon,
			    umode_t mode, char *name);
int obd_security_check_link(char *tcon, char *dcon, char *icon,
			    umode_t mode, char *name);
int obd_security_check_rename(char *tcon, char *old_name, char *new_name,
			      char *old_dcon, char *old_icon,
			      char *new_dcon, char *new_icon,
			      umode_t old_imode, umode_t new_imode,
			      bool same_dirs, bool new_i_exists);
int obd_security_check_unlink(char *tcon, char *dcon, char *icon,
			      umode_t mode, char *name);
int obd_security_check_readlink(char *tcon, char *ocon, umode_t mode, char *name);
int obd_security_check_setxattr(char *tcon, char *sbcon, char *icon,
				umode_t mode, char *fname,
				void *value, size_t size, char *name,
				__u64 capa, __u32 fsuid, __u32 iuid);
int obd_security_check_removexattr(char *tcon, char *icon, umode_t mode,
				   char *fname, char *name, __u64 capa);
int obd_security_check_getxattr(char *tcon, char *ocon, umode_t mode, char *name);
int obd_security_check_listxattr(char *tcon, char *ocon, umode_t mode, char *name);
int obd_security_init_object(char *mcon, char *dcon, char *tcon, char *tccon,
			     umode_t mode, void **value);

int obd_security_from_inode(struct inode *inode, char *label);
int obd_security_file_default_label(char *seclabel);

int obd_security_get_create_label(char **value);
#endif
