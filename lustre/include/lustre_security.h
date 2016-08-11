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
int obd_security_check_flags(char *tcon, char *ocon, char *fcon,
		             umode_t mode, char *name);
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
int obd_security_check_mount(char *tcon, char *sbcon, char *name);
int obd_security_check_quotamod(char *tcon, char *sbcon, char *name);
int obd_security_check_getquota(char *tcon, char *sbcon, char *name);
int obd_security_check_setxattr(char *tcon, char *sbcon, char *icon,
				umode_t mode, char *fname,
				void *value, size_t size, char *name,
				__u64 capa, __u32 fsuid, __u32 iuid);
int obd_security_check_removexattr(char *tcon, char *icon, umode_t mode,
				   char *fname, char *name, __u64 capa);
int obd_security_check_getxattr(char *tcon, char *ocon, umode_t mode, char *name);
int obd_security_check_check_flags(char *tcon, char *ocon, umode_t mode, char *name);
int obd_security_check_listxattr(char *tcon, char *ocon, umode_t mode, char *name);
int obd_security_init_object(char *mcon, char *dcon, char *tcon, char *tccon,
			     umode_t mode, void **value);

int obd_security_from_inode(struct inode *inode, char *label);
int obd_security_file_default_label(char *seclabel);

int obd_security_get_create_label(char **value);

/**
 * Split MDS policy defintiions
 *
 * TODO: Consider using a separate header file for these
 *
 * \addtogoup split MDS policy
 * @{
 */
/**
 * SEC message type
 *
 * These are the types of messages supported by the SEC layer for SELinux
 * policy-related operations; they are used for bidirectional communications
 * between the Lustre SEC layer and the userspace utility that will make access
 * decisions on behalf of the customer's policy.
 */
enum sec_msg_type {
	/** Requst an SID for a given context */
	SEC_MSG_SID_REQUEST,
	/** Reply containing the SID for a given context */
	SEC_MSG_SID_REPLY,
	/** Request an access vector for a given source ID:target ID: class ID
	 *  tuple
	 */
	SEC_MSG_AVC_REQUEST,
	/** Reply containing an access vector */
	SEC_MSG_AVC_REPLY,
	/** List of classes supported by a policy
	 * TODO: Consider having replies for the two following message types?
	 */
	SEC_MSG_CLASSES,
	/** Invalidate SID and AVC caches */
	SEC_MSG_CACHE_INVAL,
	SEC_MSG_MAX,
};

struct sec_msg_base {
	/** The type of sec request; TODO: either cast from
	 * \a enum sec_msg_type, or use that type instead of __u8 */
	__u8	sm_type;
	/** Flags; reserved for future use */
	__u8	sm_flags;
	/* The number of octects following in the sec_message */
	__u16	sm_length;
};


/**
 * SEC message definitions
 *
 * These are the definitions for the messages that are sent through the communications
 */
struct sec_msg_sid_request {
	struct sec_msg_base	sm_base;
	/** Transaction number for this request; a monotonically-increasing
	 * integer.
	 *
	 * TODO: We may elect to keep a separate count for the SEC and UPM?
	 */
	__u32			sm_transno;
	/** The SID for the SELinux context requested in the \a sm_transno*/
	__u32			sm_sid;

} __attribute__((packed));

struct sec_msg_sid_reply {
	struct sec_msg_base	sm_base;
	/** Transaction number for this request */
	__u32			sm_transno;
	/** The SELinux context for which we are requesting an SID */
	const char * const	sm_ctx;

} __attribute__((packed));

struct sec_msg_avc_request {
	struct sec_msg_base	sm_base;
	/** Transaction number for this request */
	__u32			sm_transno;
	/** Source ID, i.e. the domain that is making the request */
	__u32			sm_ssid;
	/** Target ID of the filesystem resource that the source ID \a sm_ssid
	 * is requesting to access
	 */
	__u32			sm_tsid;
	/** The class identifier for the type of access being requested */
	__u32			sm_classid;
} __attribute__((packed));

struct sec_msg_avc_reply {
	struct sec_msg_base	sm_base;
	/** Transaction number for this request */
	__u32			sm_transno;
	/** Class-specific bitmap of permissions allowed */
	__u32			sm_allowed;
	/** Class-specific-bitmap of permissions to be audited when allowed */
	__u32			sm_auditallow;
	/** Class-specific bitmap of permissions to not be audited when denied */
	__u32			sm_auditdeny;
	__u32			sm_avflags;
} __attribute__((packed));

struct sec_msg_classes {
	struct sec_msg_base	sm_base;
	/** Lst of classes defined by the policy, in numerical order */
	const char * const	sm_classes;
} __attribute__((packed));

struct sec_msg_cache_inval {
	struct sec_msg_base	sm_base;
} __attribute__((packed));

/** @} split MDS policy */
#endif
