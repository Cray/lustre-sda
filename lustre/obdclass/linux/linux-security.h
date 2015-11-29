#ifndef __LINUX_SECURITY_H__
#define __LINUX_SECURITY_H__

enum obd_secclass {
	OBD_SECCLASS_DIR,
	OBD_SECCLASS_FS,
	OBD_SECCLASS_FD,
	OBD_SECCLASS_FILE,
	OBD_SECCLASS_SOCK_FILE,
	OBD_SECCLASS_LNK_FILE,
	OBD_SECCLASS_CHR_FILE,
	OBD_SECCLASS_BLK_FILE,
	OBD_SECCLASS_FIFO_FILE,
	OBD_SECCLASS_MAX
};

/* Common file perms should have identical numbers between classes! */
enum {
	OBD_SECPERM_FILE_IOCTL,
	OBD_SECPERM_FILE_READ,
	OBD_SECPERM_FILE_WRITE,
	OBD_SECPERM_FILE_CREATE,
	OBD_SECPERM_FILE_GETATTR,
	OBD_SECPERM_FILE_SETATTR,
	OBD_SECPERM_FILE_LOCK,
	OBD_SECPERM_FILE_RELABELFROM,
	OBD_SECPERM_FILE_RELABELTO,
	OBD_SECPERM_FILE_APPEND,
	OBD_SECPERM_FILE_UNLINK,
	OBD_SECPERM_FILE_LINK,
	OBD_SECPERM_FILE_RENAME,
	OBD_SECPERM_FILE_EXECUTE,
	OBD_SECPERM_FILE_OPEN,
};

enum {
	OBD_SECPERM_SOCK_FILE_IOCTL,
	OBD_SECPERM_SOCK_FILE_READ,
	OBD_SECPERM_SOCK_FILE_WRITE,
	OBD_SECPERM_SOCK_FILE_CREATE,
	OBD_SECPERM_SOCK_FILE_GETATTR,
	OBD_SECPERM_SOCK_FILE_SETATTR,
	OBD_SECPERM_SOCK_FILE_LOCK,
	OBD_SECPERM_SOCK_FILE_RELABELFROM,
	OBD_SECPERM_SOCK_FILE_RELABELTO,
	OBD_SECPERM_SOCK_FILE_APPEND,
	OBD_SECPERM_SOCK_FILE_UNLINK,
	OBD_SECPERM_SOCK_FILE_LINK,
	OBD_SECPERM_SOCK_FILE_RENAME,
	OBD_SECPERM_SOCK_FILE_EXECUTE,
	OBD_SECPERM_SOCK_FILE_OPEN,
};

enum {
	OBD_SECPERM_LNK_FILE_IOCTL,
	OBD_SECPERM_LNK_FILE_READ,
	OBD_SECPERM_LNK_FILE_WRITE,
	OBD_SECPERM_LNK_FILE_CREATE,
	OBD_SECPERM_LNK_FILE_GETATTR,
	OBD_SECPERM_LNK_FILE_SETATTR,
	OBD_SECPERM_LNK_FILE_LOCK,
	OBD_SECPERM_LNK_FILE_RELABELFROM,
	OBD_SECPERM_LNK_FILE_RELABELTO,
	OBD_SECPERM_LNK_FILE_APPEND,
	OBD_SECPERM_LNK_FILE_UNLINK,
	OBD_SECPERM_LNK_FILE_LINK,
	OBD_SECPERM_LNK_FILE_RENAME,
	OBD_SECPERM_LNK_FILE_EXECUTE,
};

enum {
	OBD_SECPERM_CHR_FILE_IOCTL,
	OBD_SECPERM_CHR_FILE_READ,
	OBD_SECPERM_CHR_FILE_WRITE,
	OBD_SECPERM_CHR_FILE_CREATE,
	OBD_SECPERM_CHR_FILE_GETATTR,
	OBD_SECPERM_CHR_FILE_SETATTR,
	OBD_SECPERM_CHR_FILE_LOCK,
	OBD_SECPERM_CHR_FILE_RELABELFROM,
	OBD_SECPERM_CHR_FILE_RELABELTO,
	OBD_SECPERM_CHR_FILE_APPEND,
	OBD_SECPERM_CHR_FILE_UNLINK,
	OBD_SECPERM_CHR_FILE_LINK,
	OBD_SECPERM_CHR_FILE_RENAME,
	OBD_SECPERM_CHR_FILE_EXECUTE,
	OBD_SECPERM_CHR_FILE_OPEN,
};

enum {
	OBD_SECPERM_BLK_FILE_IOCTL,
	OBD_SECPERM_BLK_FILE_READ,
	OBD_SECPERM_BLK_FILE_WRITE,
	OBD_SECPERM_BLK_FILE_CREATE,
	OBD_SECPERM_BLK_FILE_GETATTR,
	OBD_SECPERM_BLK_FILE_SETATTR,
	OBD_SECPERM_BLK_FILE_LOCK,
	OBD_SECPERM_BLK_FILE_RELABELFROM,
	OBD_SECPERM_BLK_FILE_RELABELTO,
	OBD_SECPERM_BLK_FILE_APPEND,
	OBD_SECPERM_BLK_FILE_UNLINK,
	OBD_SECPERM_BLK_FILE_LINK,
	OBD_SECPERM_BLK_FILE_RENAME,
	OBD_SECPERM_BLK_FILE_EXECUTE,
	OBD_SECPERM_BLK_FILE_OPEN,
};

enum {
	OBD_SECPERM_FIFO_FILE_IOCTL,
	OBD_SECPERM_FIFO_FILE_READ,
	OBD_SECPERM_FIFO_FILE_WRITE,
	OBD_SECPERM_FIFO_FILE_CREATE,
	OBD_SECPERM_FIFO_FILE_GETATTR,
	OBD_SECPERM_FIFO_FILE_SETATTR,
	OBD_SECPERM_FIFO_FILE_LOCK,
	OBD_SECPERM_FIFO_FILE_RELABELFROM,
	OBD_SECPERM_FIFO_FILE_RELABELTO,
	OBD_SECPERM_FIFO_FILE_APPEND,
	OBD_SECPERM_FIFO_FILE_UNLINK,
	OBD_SECPERM_FIFO_FILE_LINK,
	OBD_SECPERM_FIFO_FILE_RENAME,
	OBD_SECPERM_FIFO_FILE_EXECUTE,
	OBD_SECPERM_FIFO_FILE_OPEN,
};

enum {
	OBD_SECPERM_DIR_IOCTL,
	OBD_SECPERM_DIR_READ,
	OBD_SECPERM_DIR_WRITE,
	OBD_SECPERM_DIR_CREATE,
	OBD_SECPERM_DIR_GETATTR,
	OBD_SECPERM_DIR_SETATTR,
	OBD_SECPERM_DIR_LOCK,
	OBD_SECPERM_DIR_RELABELFROM,
	OBD_SECPERM_DIR_RELABELTO,
	OBD_SECPERM_DIR_APPEND,
	OBD_SECPERM_DIR_UNLINK,
	OBD_SECPERM_DIR_LINK,
	OBD_SECPERM_DIR_RENAME,
	OBD_SECPERM_DIR_EXECUTE,
	OBD_SECPERM_DIR_OPEN,

	OBD_SECPERM_DIR_ADDNAME,
	OBD_SECPERM_DIR_REMOVENAME,
	OBD_SECPERM_DIR_SEARCH,
	OBD_SECPERM_DIR_RMDIR,
	OBD_SECPERM_DIR_REPARENT,
};

enum {
	OBD_SECPERM_FS_ASSOCIATE,
	OBD_SECPERM_FS_MOUNT
};

enum {
	OBD_SECPERM_FD_USE
};

struct obd_secperms_map_s {
	char	*name;
	u64	policy_perm;
};

struct obd_secclass_map_s {
	char	*name;
	struct	obd_secperms_map_s perm[32];
	u64	policy_class;
} obd_secclass_map[OBD_SECCLASS_MAX] = {
	[OBD_SECCLASS_DIR] = { "dir", {
					[OBD_SECPERM_DIR_OPEN] = { "open" },
					[OBD_SECPERM_DIR_IOCTL] = { "ioctl" },
					[OBD_SECPERM_DIR_READ] = { "read" },
					[OBD_SECPERM_DIR_WRITE] = { "write" },
					[OBD_SECPERM_DIR_CREATE] = { "create" },
					[OBD_SECPERM_DIR_GETATTR] = { "getattr" },
					[OBD_SECPERM_DIR_SETATTR] = { "setattr" },
					[OBD_SECPERM_DIR_LINK] = { "link" },
					[OBD_SECPERM_DIR_UNLINK] = { "unlink" },
					[OBD_SECPERM_DIR_RENAME] = { "rename" },
					[OBD_SECPERM_DIR_LOCK] = { "lock" } ,
					[OBD_SECPERM_DIR_RELABELFROM] = { "relabelfrom" },
					[OBD_SECPERM_DIR_RELABELTO] = { "relabelto" },
					[OBD_SECPERM_DIR_EXECUTE] = { "execute" },
					[OBD_SECPERM_DIR_APPEND] = { "append" },

					[OBD_SECPERM_DIR_ADDNAME] = { "add_name" },
					[OBD_SECPERM_DIR_REMOVENAME] = { "remove_name" },
					[OBD_SECPERM_DIR_SEARCH] = { "search" },
					[OBD_SECPERM_DIR_RMDIR] = { "rmdir" },
					[OBD_SECPERM_DIR_REPARENT] = { "reparent" },
					[OBD_SECPERM_DIR_OPEN] = { "open" },
					[OBD_SECPERM_DIR_READ] = { "read" },
					[OBD_SECPERM_DIR_WRITE] = { "write" },
				      }
			     },
	[OBD_SECCLASS_FS] = { "filesystem", {
					[OBD_SECPERM_FS_ASSOCIATE] = { "associate" },
					[OBD_SECPERM_FS_MOUNT] = { "mount" }
					}
				    },
	[OBD_SECCLASS_FD] = { "fd", {
					[OBD_SECPERM_FD_USE] = { "use" }
				    }
			    },
	[OBD_SECCLASS_FILE] = { "file", {
					[OBD_SECPERM_FILE_OPEN] = { "open" },
					[OBD_SECPERM_FILE_IOCTL] = { "ioctl" },
					[OBD_SECPERM_FILE_READ] = { "read" },
					[OBD_SECPERM_FILE_WRITE] = { "write" },
					[OBD_SECPERM_FILE_CREATE] = { "create" },
					[OBD_SECPERM_FILE_GETATTR] = { "getattr" },
					[OBD_SECPERM_FILE_SETATTR] = { "setattr" },
					[OBD_SECPERM_FILE_LINK] = { "link" },
					[OBD_SECPERM_FILE_UNLINK] = { "unlink" },
					[OBD_SECPERM_FILE_RENAME] = { "rename" },
					[OBD_SECPERM_FILE_LOCK] = { "lock" } ,
					[OBD_SECPERM_FILE_RELABELFROM] = { "relabelfrom" },
					[OBD_SECPERM_FILE_RELABELTO] = { "relabelto" },
					[OBD_SECPERM_FILE_EXECUTE] = { "execute" },
					[OBD_SECPERM_FILE_APPEND] = { "append" }
				}
			      },
	[OBD_SECCLASS_SOCK_FILE] = { "sock_file", {
					[OBD_SECPERM_SOCK_FILE_OPEN] = { "open" },
					[OBD_SECPERM_SOCK_FILE_IOCTL] = { "ioctl" },
					[OBD_SECPERM_SOCK_FILE_READ] = { "read" },
					[OBD_SECPERM_SOCK_FILE_WRITE] = { "write" },
					[OBD_SECPERM_SOCK_FILE_CREATE] = { "create" },
					[OBD_SECPERM_SOCK_FILE_GETATTR] = { "getattr" },
					[OBD_SECPERM_SOCK_FILE_SETATTR] = { "setattr" },
					[OBD_SECPERM_SOCK_FILE_LINK] = { "link" },
					[OBD_SECPERM_SOCK_FILE_UNLINK] = { "unlink" },
					[OBD_SECPERM_SOCK_FILE_RENAME] = { "rename" },
					[OBD_SECPERM_SOCK_FILE_LOCK] = { "lock" } ,
					[OBD_SECPERM_SOCK_FILE_RELABELFROM] = { "relabelfrom" },
					[OBD_SECPERM_SOCK_FILE_RELABELTO] = { "relabelto" },
					[OBD_SECPERM_SOCK_FILE_EXECUTE] = { "execute" },
					[OBD_SECPERM_SOCK_FILE_APPEND] = { "append" }
				}
			      },
	[OBD_SECCLASS_LNK_FILE] = { "lnk_file", {
					[OBD_SECPERM_LNK_FILE_IOCTL] = { "ioctl" },
					[OBD_SECPERM_LNK_FILE_READ] = { "read" },
					[OBD_SECPERM_LNK_FILE_WRITE] = { "write" },
					[OBD_SECPERM_LNK_FILE_CREATE] = { "create" },
					[OBD_SECPERM_LNK_FILE_GETATTR] = { "getattr" },
					[OBD_SECPERM_LNK_FILE_SETATTR] = { "setattr" },
					[OBD_SECPERM_LNK_FILE_LINK] = { "link" },
					[OBD_SECPERM_LNK_FILE_UNLINK] = { "unlink" },
					[OBD_SECPERM_LNK_FILE_RENAME] = { "rename" },
					[OBD_SECPERM_LNK_FILE_LOCK] = { "lock" } ,
					[OBD_SECPERM_LNK_FILE_RELABELFROM] = { "relabelfrom" },
					[OBD_SECPERM_LNK_FILE_RELABELTO] = { "relabelto" },
					[OBD_SECPERM_LNK_FILE_EXECUTE] = { "execute" },
					[OBD_SECPERM_LNK_FILE_APPEND] = { "append" }
				}
			      },
	[OBD_SECCLASS_CHR_FILE] = { "chr_file", {
					[OBD_SECPERM_CHR_FILE_OPEN] = { "open" },
					[OBD_SECPERM_CHR_FILE_IOCTL] = { "ioctl" },
					[OBD_SECPERM_CHR_FILE_READ] = { "read" },
					[OBD_SECPERM_CHR_FILE_WRITE] = { "write" },
					[OBD_SECPERM_CHR_FILE_CREATE] = { "create" },
					[OBD_SECPERM_CHR_FILE_GETATTR] = { "getattr" },
					[OBD_SECPERM_CHR_FILE_SETATTR] = { "setattr" },
					[OBD_SECPERM_CHR_FILE_LINK] = { "link" },
					[OBD_SECPERM_CHR_FILE_UNLINK] = { "unlink" },
					[OBD_SECPERM_CHR_FILE_RENAME] = { "rename" },
					[OBD_SECPERM_CHR_FILE_LOCK] = { "lock" } ,
					[OBD_SECPERM_CHR_FILE_RELABELFROM] = { "relabelfrom" },
					[OBD_SECPERM_CHR_FILE_RELABELTO] = { "relabelto" },
					[OBD_SECPERM_CHR_FILE_EXECUTE] = { "execute" },
					[OBD_SECPERM_CHR_FILE_APPEND] = { "append" }
				}
			      },
	[OBD_SECCLASS_BLK_FILE] = { "blk_file", {
					[OBD_SECPERM_BLK_FILE_OPEN] = { "open" },
					[OBD_SECPERM_BLK_FILE_IOCTL] = { "ioctl" },
					[OBD_SECPERM_BLK_FILE_READ] = { "read" },
					[OBD_SECPERM_BLK_FILE_WRITE] = { "write" },
					[OBD_SECPERM_BLK_FILE_CREATE] = { "create" },
					[OBD_SECPERM_BLK_FILE_GETATTR] = { "getattr" },
					[OBD_SECPERM_BLK_FILE_SETATTR] = { "setattr" },
					[OBD_SECPERM_BLK_FILE_LINK] = { "link" },
					[OBD_SECPERM_BLK_FILE_UNLINK] = { "unlink" },
					[OBD_SECPERM_BLK_FILE_RENAME] = { "rename" },
					[OBD_SECPERM_BLK_FILE_LOCK] = { "lock" } ,
					[OBD_SECPERM_BLK_FILE_RELABELFROM] = { "relabelfrom" },
					[OBD_SECPERM_BLK_FILE_RELABELTO] = { "relabelto" },
					[OBD_SECPERM_BLK_FILE_EXECUTE] = { "execute" },
					[OBD_SECPERM_BLK_FILE_APPEND] = { "append" }
				}
			      },
	[OBD_SECCLASS_FIFO_FILE] = { "fifo_file", {
					[OBD_SECPERM_FIFO_FILE_OPEN] = { "open" },
					[OBD_SECPERM_FIFO_FILE_IOCTL] = { "ioctl" },
					[OBD_SECPERM_FIFO_FILE_READ] = { "read" },
					[OBD_SECPERM_FIFO_FILE_WRITE] = { "write" },
					[OBD_SECPERM_FIFO_FILE_CREATE] = { "create" },
					[OBD_SECPERM_FIFO_FILE_GETATTR] = { "getattr" },
					[OBD_SECPERM_FIFO_FILE_SETATTR] = { "setattr" },
					[OBD_SECPERM_FIFO_FILE_LINK] = { "link" },
					[OBD_SECPERM_FIFO_FILE_UNLINK] = { "unlink" },
					[OBD_SECPERM_FIFO_FILE_RENAME] = { "rename" },
					[OBD_SECPERM_FIFO_FILE_LOCK] = { "lock" } ,
					[OBD_SECPERM_FIFO_FILE_RELABELFROM] = { "relabelfrom" },
					[OBD_SECPERM_FIFO_FILE_RELABELTO] = { "relabelto" },
					[OBD_SECPERM_FIFO_FILE_EXECUTE] = { "execute" },
					[OBD_SECPERM_FIFO_FILE_APPEND] = { "append" }
				}
			      },

};

static inline u16 inode_mode_to_security_class(umode_t mode)
{
	switch (mode & S_IFMT) {
	case S_IFSOCK:
		return OBD_SECCLASS_SOCK_FILE;
	case S_IFLNK:
		return OBD_SECCLASS_LNK_FILE;
	case S_IFREG:
		return OBD_SECCLASS_FILE;
	case S_IFBLK:
		return OBD_SECCLASS_BLK_FILE;
	case S_IFDIR:
		return OBD_SECCLASS_DIR;
	case S_IFCHR:
		return OBD_SECCLASS_CHR_FILE;
	case S_IFIFO:
		return OBD_SECCLASS_FIFO_FILE;
	}

	return OBD_SECCLASS_FILE;
}

/* Convert a Linux file to an access vector. */
static inline u32 file_to_av(fmode_t fmode, unsigned fflags)
{
	u32 av = 0;

	if (fmode & FMODE_READ)
		av |= 1 << OBD_SECPERM_FILE_READ;
	if (fmode & FMODE_WRITE) {
		if (fflags & O_APPEND)
			av |= 1 << OBD_SECPERM_FILE_APPEND;
		else
			av |= 1 << OBD_SECPERM_FILE_WRITE;
	}
	if (av == 0) {
		/*
		 * Special file opened with flags 3 for ioctl-only use.
		 */
		av = 1 << OBD_SECPERM_FILE_IOCTL;
	}

	return av;
}

static inline u32 open_inode_to_av(unsigned mode)
{
	if (obd_security_openperm) {
		/*
		 * lnk files and socks do not really have an 'open'
		 */
		if (S_ISREG(mode))
			return 1 << OBD_SECPERM_FILE_OPEN;
		else if (S_ISCHR(mode))
			return 1 << OBD_SECPERM_CHR_FILE_OPEN;
		else if (S_ISBLK(mode))
			return 1 << OBD_SECPERM_BLK_FILE_OPEN;
		else if (S_ISFIFO(mode))
			return 1 << OBD_SECPERM_FIFO_FILE_OPEN;
		else if (S_ISDIR(mode))
			return 1 << OBD_SECPERM_DIR_OPEN;
		else if (S_ISSOCK(mode))
			return 1 << OBD_SECPERM_SOCK_FILE_OPEN;
		else
			printk(KERN_ERR "SELinux: WARNING: inside %s with "
				"unknown mode:%o\n", __func__, mode);
	}

	return 0;
}

/*
 * Convert a file to an access vector and include the correct
 * open permission.
 */
static inline u32 open_file_to_av(fmode_t fmode, unsigned fflags,
				  unsigned imode)
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
			av |= OBD_SECPERM_FILE_EXECUTE;
		if (mask & MAY_READ)
			av |= OBD_SECPERM_FILE_READ;

		if (mask & MAY_APPEND)
			av |= OBD_SECPERM_FILE_APPEND;
		else if (mask & MAY_WRITE)
			av |= OBD_SECPERM_FILE_WRITE;

	} else {
		if (mask & MAY_EXEC)
			av |= OBD_SECPERM_DIR_SEARCH;
		if (mask & MAY_WRITE)
			av |= OBD_SECPERM_DIR_WRITE;
		if (mask & MAY_READ)
			av |= OBD_SECPERM_DIR_READ;
	}

	return av;
}

#endif
