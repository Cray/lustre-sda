#include <obd.h>
#include <lustre_fld.h>
#include <md_object.h>
#include <lustre_acl.h>
#include <lustre_security.h>

/**
 * md_device extention for security layer.
 */
struct sec_device {
	/** md_device instance */
	struct md_device sec_md_dev;
	/** device flags, taken from enum sec_flags */
	__u32 sec_flags;
	/** underlaying device in MDS stack, MDD */
	struct md_device *sec_child;
	struct obd_export *sec_child_exp;
	/** FLD client to talk to FLD */
	struct lu_client_fld *sec_fld;
	/** /proc entry with security data */
	struct proc_dir_entry *sec_proc_entry;
	/** security statistic */
	struct lprocfs_stats *sec_stats;
};

struct sec_object {
	struct md_object sec_obj;
};

/**
 * security flags
 */
enum sec_flags {
	/** Device initialization complete. */
	SEC_INITIALIZED = 1 << 0
};

/**
 * security thread info.
 * This is storage for all variables used in security functions and
 * it is needed as stack replacement.
 */
struct sec_thread_info {
};

static inline struct sec_device *lu2sec_dev(struct lu_device *d)
{
	return container_of0(d, struct sec_device, sec_md_dev.md_lu_dev);
}

static inline struct sec_object *md2sec_obj(struct md_object *o)
{
	return container_of0(o, struct sec_object, sec_obj);
}

static inline struct lu_device *sec2lu_dev(struct sec_device *d)
{
	return (&d->sec_md_dev.md_lu_dev);
}


struct lu_object *sec_object_alloc(const struct lu_env *env,
				   const struct lu_object_header *hdr,
				   struct lu_device *);

static inline struct sec_object *lu2sec_obj(struct lu_object *o)
{
	return container_of0(o, struct sec_object, sec_obj.mo_lu);
}

static inline struct sec_device *md2sec_dev(struct md_device *m)
{
	return container_of0(m, struct sec_device, sec_md_dev);
}

static inline const struct md_device_operations *sec_child_ops(struct
							       sec_device
							       *d)
{
	return d->sec_child->md_ops;
}

/**
 * Extract lu_fid from corresponding sec_object.
 */
static inline struct lu_fid* sec2fid(struct sec_object *obj)
{
       return &(obj->sec_obj.mo_lu.lo_header->loh_fid);
}
