#include <obd_class.h>
#include <lustre_ver.h>
#include "sec_internal.h"
#ifdef HAVE_QUOTA_SUPPORT
# include <lustre_quota.h>
#endif

struct obd_ops sec_obd_device_ops = {
	.o_owner = THIS_MODULE
};

int sec_root_get(const struct lu_env *env, struct md_device *md,
		 struct lu_fid *fid)
{
	struct sec_device *sec_dev = md2sec_dev(md);

	return sec_child_ops(sec_dev)->mdo_root_get(env,
						    sec_dev->sec_child,
						    fid);
}

static int sec_statfs(const struct lu_env *env, struct md_device *md,
		      struct obd_statfs *sfs)
{
	struct sec_device *sec_dev = md2sec_dev(md);
	int rc;

	ENTRY;
	rc = sec_child_ops(sec_dev)->mdo_statfs(env,
						sec_dev->sec_child, sfs);
	RETURN(rc);
}

static int sec_maxsize_get(const struct lu_env *env, struct md_device *md,
			   int *md_size, int *cookie_size)
{
	struct sec_device *sec_dev = md2sec_dev(md);
	int rc;
	ENTRY;
	rc = sec_child_ops(sec_dev)->mdo_maxsize_get(env,
						     sec_dev->sec_child,
						     md_size, cookie_size);
	RETURN(rc);
}

static int sec_init_capa_ctxt(const struct lu_env *env,
			      struct md_device *md, int mode,
			      unsigned long timeout, __u32 alg,
			      struct lustre_capa_key *keys)
{
	struct sec_device *sec_dev = md2sec_dev(md);
	int rc;
	ENTRY;
	LASSERT(sec_child_ops(sec_dev)->mdo_init_capa_ctxt);
	rc = sec_child_ops(sec_dev)->mdo_init_capa_ctxt(env,
							sec_dev->sec_child,
							mode, timeout, alg,
							keys);
	RETURN(rc);
}

static int sec_update_capa_key(const struct lu_env *env,
			       struct md_device *md,
			       struct lustre_capa_key *key)
{
	struct sec_device *sec_dev = md2sec_dev(md);
	int rc;
	ENTRY;
	rc = sec_child_ops(sec_dev)->mdo_update_capa_key(env,
							 sec_dev->
							 sec_child, key);
	RETURN(rc);
}

static int sec_llog_ctxt_get(const struct lu_env *env, struct md_device *m,
			     int idx, void **h)
{
	struct sec_device *sec_dev = md2sec_dev(m);
	int rc;
	ENTRY;

	rc = sec_child_ops(sec_dev)->mdo_llog_ctxt_get(env,
						       sec_dev->sec_child,
						       idx, h);
	RETURN(rc);
}

#ifdef HAVE_QUOTA_SUPPORT
/**
 * \name Quota functions
 * @{
 */
static int sec_quota_notify(const struct lu_env *env, struct md_device *m)
{
	struct sec_device *sec_dev = md2sec_dev(m);
	int rc;
	ENTRY;

	rc = sec_child_ops(sec_dev)->mdo_quota.mqo_notify(env,
							  sec_dev->
							  sec_child);
	RETURN(rc);
}

static int sec_quota_setup(const struct lu_env *env, struct md_device *m,
			   void *data)
{
	struct sec_device *sec_dev = md2sec_dev(m);
	int rc;
	ENTRY;

	rc = sec_child_ops(sec_dev)->mdo_quota.mqo_setup(env,
							 sec_dev->
							 sec_child, data);
	RETURN(rc);
}

static int sec_quota_cleanup(const struct lu_env *env, struct md_device *m)
{
	struct sec_device *sec_dev = md2sec_dev(m);
	int rc;
	ENTRY;

	rc = sec_child_ops(sec_dev)->mdo_quota.mqo_cleanup(env,
							   sec_dev->
							   sec_child);
	RETURN(rc);
}

static int sec_quota_recovery(const struct lu_env *env,
			      struct md_device *m)
{
	struct sec_device *sec_dev = md2sec_dev(m);
	int rc;
	ENTRY;

	rc = sec_child_ops(sec_dev)->mdo_quota.mqo_recovery(env,
							    sec_dev->
							    sec_child);
	RETURN(rc);
}

static int sec_quota_check(const struct lu_env *env, struct md_device *m,
			   __u32 type)
{
	struct sec_device *sec_dev = md2sec_dev(m);
	int rc;
	ENTRY;

	rc = sec_child_ops(sec_dev)->mdo_quota.mqo_check(env,
							 sec_dev->
							 sec_child, type);
	RETURN(rc);
}

static int sec_quota_on(const struct lu_env *env, struct md_device *m,
			__u32 type)
{
	struct sec_device *sec_dev = md2sec_dev(m);
	int rc;
	ENTRY;

	rc = sec_child_ops(sec_dev)->mdo_quota.mqo_on(env,
						      sec_dev->sec_child,
						      type);
	RETURN(rc);
}

static int sec_quota_off(const struct lu_env *env, struct md_device *m,
			 __u32 type)
{
	struct sec_device *sec_dev = md2sec_dev(m);
	int rc;
	ENTRY;

	rc = sec_child_ops(sec_dev)->mdo_quota.mqo_off(env,
						       sec_dev->sec_child,
						       type);
	RETURN(rc);
}

static int sec_quota_setinfo(const struct lu_env *env, struct md_device *m,
			     __u32 type, __u32 id,
			     struct obd_dqinfo *dqinfo)
{
	struct sec_device *sec_dev = md2sec_dev(m);
	int rc;
	ENTRY;

	rc = sec_child_ops(sec_dev)->mdo_quota.mqo_setinfo(env,
							   sec_dev->
							   sec_child, type,
							   id, dqinfo);
	RETURN(rc);
}

static int sec_quota_getinfo(const struct lu_env *env,
			     const struct md_device *m,
			     __u32 type, __u32 id,
			     struct obd_dqinfo *dqinfo)
{
	struct sec_device *sec_dev = md2sec_dev((struct md_device *) m);
	int rc;
	ENTRY;

	rc = sec_child_ops(sec_dev)->mdo_quota.mqo_getinfo(env,
							   sec_dev->
							   sec_child, type,
							   id, dqinfo);
	RETURN(rc);
}

static int sec_quota_setquota(const struct lu_env *env,
			      struct md_device *m, __u32 type, __u32 id,
			      struct obd_dqblk *dqblk)
{
	struct sec_device *sec_dev = md2sec_dev(m);
	int rc;
	ENTRY;

	rc = sec_child_ops(sec_dev)->mdo_quota.mqo_setquota(env,
							    sec_dev->
							    sec_child,
							    type, id,
							    dqblk);
	RETURN(rc);
}

static int sec_quota_getquota(const struct lu_env *env,
			      const struct md_device *m,
			      __u32 type, __u32 id,
			      struct obd_dqblk *dqblk)
{
	struct sec_device *sec_dev = md2sec_dev((struct md_device *) m);
	int rc;
	ENTRY;

	rc = sec_child_ops(sec_dev)->mdo_quota.mqo_getquota(env,
							    sec_dev->
							    sec_child,
							    type, id,
							    dqblk);
	RETURN(rc);
}

static int sec_quota_getoinfo(const struct lu_env *env,
			      const struct md_device *m,
			      __u32 type, __u32 id,
			      struct obd_dqinfo *dqinfo)
{
	struct sec_device *sec_dev = md2sec_dev((struct md_device *) m);
	int rc;
	ENTRY;

	rc = sec_child_ops(sec_dev)->mdo_quota.mqo_getoinfo(env,
							    sec_dev->
							    sec_child,
							    type, id,
							    dqinfo);
	RETURN(rc);
}

static int sec_quota_getoquota(const struct lu_env *env,
			       const struct md_device *m,
			       __u32 type, __u32 id,
			       struct obd_dqblk *dqblk)
{
	struct sec_device *sec_dev = md2sec_dev((struct md_device *) m);
	int rc;
	ENTRY;

	rc = sec_child_ops(sec_dev)->mdo_quota.mqo_getoquota(env,
							     sec_dev->
							     sec_child,
							     type, id,
							     dqblk);
	RETURN(rc);
}

static int sec_quota_invalidate(const struct lu_env *env,
				struct md_device *m, __u32 type)
{
	struct sec_device *sec_dev = md2sec_dev(m);
	int rc;
	ENTRY;

	rc = sec_child_ops(sec_dev)->mdo_quota.mqo_invalidate(env,
							      sec_dev->
							      sec_child,
							      type);
	RETURN(rc);
}

static int sec_quota_finvalidate(const struct lu_env *env,
				 struct md_device *m, __u32 type)
{
	struct sec_device *sec_dev = md2sec_dev(m);
	int rc;
	ENTRY;

	rc = sec_child_ops(sec_dev)->mdo_quota.mqo_finvalidate(env,
							       sec_dev->
							       sec_child,
							       type);
	RETURN(rc);
}

/** @} */
#endif

int sec_iocontrol(const struct lu_env *env, struct md_device *m,
		  unsigned int cmd, int len, void *data)
{
	struct md_device *next = md2sec_dev(m)->sec_child;
	int rc;

	ENTRY;
	rc = next->md_ops->mdo_iocontrol(env, next, cmd, len, data);
	RETURN(rc);
}



static const struct md_device_operations sec_md_ops = {
	.mdo_statfs = sec_statfs,
	.mdo_root_get = sec_root_get,
	.mdo_maxsize_get = sec_maxsize_get,
	.mdo_init_capa_ctxt = sec_init_capa_ctxt,
	.mdo_update_capa_key = sec_update_capa_key,
	.mdo_llog_ctxt_get = sec_llog_ctxt_get,
	.mdo_iocontrol = sec_iocontrol,
#ifdef HAVE_QUOTA_SUPPORT
	.mdo_quota = {
		      .mqo_notify = sec_quota_notify,
		      .mqo_setup = sec_quota_setup,
		      .mqo_cleanup = sec_quota_cleanup,
		      .mqo_recovery = sec_quota_recovery,
		      .mqo_check = sec_quota_check,
		      .mqo_on = sec_quota_on,
		      .mqo_off = sec_quota_off,
		      .mqo_setinfo = sec_quota_setinfo,
		      .mqo_getinfo = sec_quota_getinfo,
		      .mqo_setquota = sec_quota_setquota,
		      .mqo_getquota = sec_quota_getquota,
		      .mqo_getoinfo = sec_quota_getoinfo,
		      .mqo_getoquota = sec_quota_getoquota,
		      .mqo_invalidate = sec_quota_invalidate,
		      .mqo_finvalidate = sec_quota_finvalidate}
#endif
};


static int sec_process_config(const struct lu_env *env,
			      struct lu_device *d, struct lustre_cfg *cfg)
{
	struct sec_device *m = lu2sec_dev(d);
	struct lu_device *next = md2lu_dev(m->sec_child);
	int err;
	ENTRY;

	switch (cfg->lcfg_command) {
		/* TODO: Add cases here */
	default:
		err = next->ld_ops->ldo_process_config(env, next, cfg);
	}
	RETURN(err);
}

static int sec_recovery_complete(const struct lu_env *env,
				 struct lu_device *d)
{
	struct sec_device *m = lu2sec_dev(d);
	struct lu_device *next = md2lu_dev(m->sec_child);
	int rc;
	ENTRY;
	rc = next->ld_ops->ldo_recovery_complete(env, next);
	RETURN(rc);
}

static int sec_prepare(const struct lu_env *env,
		       struct lu_device *pdev, struct lu_device *dev)
{
	struct sec_device *sec = lu2sec_dev(dev);
	struct lu_device *next = md2lu_dev(sec->sec_child);
	int rc;

	ENTRY;
	rc = next->ld_ops->ldo_prepare(env, dev, next);
	RETURN(rc);
}

static int sec_rebuild(const struct lu_env *env,
		       struct lu_device *dev, __u32 flags)
{
	struct sec_device *sec = lu2sec_dev(dev);
	struct lu_device *next = md2lu_dev(sec->sec_child);
	int rc;

	ENTRY;
	rc = next->ld_ops->ldo_rebuild(env, next, flags);
	RETURN(rc);
}

static const struct lu_device_operations sec_lu_ops = {
	.ldo_object_alloc = sec_object_alloc,
	.ldo_process_config = sec_process_config,
	.ldo_recovery_complete = sec_recovery_complete,
	.ldo_prepare = sec_prepare,
	.ldo_rebuild = sec_rebuild,
};

static struct lu_device *sec_device_free(const struct lu_env *env,
					 struct lu_device *d)
{
	struct sec_device *m = lu2sec_dev(d);
	struct lu_device *next = md2lu_dev(m->sec_child);
	ENTRY;

	if (m->sec_fld != NULL) {
                OBD_FREE_PTR(m->sec_fld);
                m->sec_fld = NULL;
        }
	md_device_fini(&m->sec_md_dev);
	OBD_FREE_PTR(m);
	RETURN(next);
}

static struct lu_device *sec_device_alloc(const struct lu_env *env,
					  struct lu_device_type *t,
					  struct lustre_cfg *cfg)
{
	struct lu_device *l;
	struct sec_device *m;
	ENTRY;

	OBD_ALLOC_PTR(m);
	if (m == NULL) {
		l = ERR_PTR(-ENOMEM);
	} else {
		md_device_init(&m->sec_md_dev, t);
		m->sec_md_dev.md_ops = &sec_md_ops;
		//md_upcall_init(&m->sec_md_dev, sec_upcall);
		l = sec2lu_dev(m);
		l->ld_ops = &sec_lu_ops;

		OBD_ALLOC_PTR(m->sec_fld);
		if (!m->sec_fld) {
			sec_device_free(env, l);
			l = ERR_PTR(-ENOMEM);
		}
	}
	RETURN(l);
}

/* context key constructor/destructor: sec_key_init, sec_key_fini */
LU_KEY_INIT_FINI(sec, struct sec_thread_info);

/* context key: sec_thread_key */
LU_CONTEXT_KEY_DEFINE(sec, LCT_MD_THREAD);

struct sec_thread_info *sec_env_info(const struct lu_env *env)
{
	struct sec_thread_info *info;

	info = lu_context_key_get(&env->le_ctx, &sec_thread_key);
	LASSERT(info != NULL);
	return info;
}


/* type constructor/destructor: sec_type_init/sec_type_fini */
LU_TYPE_INIT_FINI(sec, &sec_thread_key);

/*
 * Kludge code : it should be moved mdc_device.c if mdc_(mds)_device
 * is really stacked.
 */
static int __sec_type_init(struct lu_device_type *t)
{
	int rc;
	rc = sec_type_init(t);
	return rc;
}

static void __sec_type_fini(struct lu_device_type *t)
{
	sec_type_fini(t);
}

static void __sec_type_start(struct lu_device_type *t)
{
	sec_type_start(t);
}

static void __sec_type_stop(struct lu_device_type *t)
{
	sec_type_stop(t);
}

static int sec_device_init(const struct lu_env *env, struct lu_device *d,
			   const char *name, struct lu_device *next)
{
	struct sec_device *sec = lu2sec_dev(d);

	sec->sec_child = lu2md_dev(next);

	return 0;
}

static struct lu_device *sec_device_fini(const struct lu_env *env,
					 struct lu_device *ld)
{
	struct sec_device *sec = lu2sec_dev(ld);

	RETURN(md2lu_dev(sec->sec_child));
}


static struct lu_device_type_operations sec_device_type_ops = {
	.ldto_init = __sec_type_init,
	.ldto_fini = __sec_type_fini,

	.ldto_start = __sec_type_start,
	.ldto_stop = __sec_type_stop,

	.ldto_device_alloc = sec_device_alloc,
	.ldto_device_free = sec_device_free,

	.ldto_device_init = sec_device_init,
	.ldto_device_fini = sec_device_fini
};

static struct lu_device_type sec_device_type = {
	.ldt_tags = LU_DEVICE_MD,
	.ldt_name = LUSTRE_SEC_NAME,
	.ldt_ops = &sec_device_type_ops,
	.ldt_ctx_tags = LCT_MD_THREAD | LCT_DT_THREAD
};

struct lprocfs_vars lprocfs_sec_obd_vars[] = {
	{0}
};

struct lprocfs_vars lprocfs_sec_module_vars[] = {
	{0}
};


static void lprocfs_sec_init_vars(struct lprocfs_static_vars *lvars)
{
	lvars->module_vars = lprocfs_sec_module_vars;
	lvars->obd_vars = lprocfs_sec_obd_vars;
}

static int __init sec_mod_init(void)
{
	struct lprocfs_static_vars lvars;

	lprocfs_sec_init_vars(&lvars);
	return class_register_type(&sec_obd_device_ops, NULL,
				   lvars.module_vars, LUSTRE_SEC_NAME,
				   &sec_device_type);
}

static void __exit sec_mod_exit(void)
{
	class_unregister_type(LUSTRE_SEC_NAME);
}

MODULE_AUTHOR("Xyratex, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Security Level (" LUSTRE_SEC_NAME ")");
MODULE_LICENSE("GPL");

cfs_module(sec, "0.1.0", sec_mod_init, sec_mod_exit);
