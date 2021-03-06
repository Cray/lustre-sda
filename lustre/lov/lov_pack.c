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
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/lov/lov_pack.c
 *
 * (Un)packing of OST/MDS requests
 *
 * Author: Andreas Dilger <adilger@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_LOV
#ifndef __KERNEL__
#include <liblustre.h>
#endif

#include <lustre_net.h>
#include <obd.h>
#include <obd_lov.h>
#include <obd_class.h>
#include <obd_support.h>
#include <lustre/lustre_user.h>

#include "lov_internal.h"

static void lov_dump_lmm_common(int level, void *lmmp)
{
	struct lov_mds_md *lmm = lmmp;
	struct ost_id	oi;

	lmm_oi_le_to_cpu(&oi, &lmm->lmm_oi);
	CDEBUG(level, "objid "DOSTID", magic 0x%08x, pattern %#x\n",
	       POSTID(&oi), le32_to_cpu(lmm->lmm_magic),
	       le32_to_cpu(lmm->lmm_pattern));
	CDEBUG(level, "stripe_size %u, stripe_count %u, layout_gen %u\n",
	       le32_to_cpu(lmm->lmm_stripe_size),
	       le16_to_cpu(lmm->lmm_stripe_count),
	       le16_to_cpu(lmm->lmm_layout_gen));
}

static void lov_dump_lmm_objects(int level, struct lov_ost_data *lod,
                                 int stripe_count)
{
	int i;

	if (stripe_count > LOV_V1_INSANE_STRIPE_COUNT) {
		CDEBUG(level, "bad stripe_count %u > max_stripe_count %u\n",
		       stripe_count, LOV_V1_INSANE_STRIPE_COUNT);
	}

	for (i = 0; i < stripe_count; ++i, ++lod) {
		struct ost_id	oi;

		ostid_le_to_cpu(&lod->l_ost_oi, &oi);
		CDEBUG(level, "stripe %u idx %u subobj "DOSTID"\n", i,
		       le32_to_cpu(lod->l_ost_idx), POSTID(&oi));
	}
}

void lov_dump_lmm_v1(int level, struct lov_mds_md_v1 *lmm)
{
        lov_dump_lmm_common(level, lmm);
        lov_dump_lmm_objects(level, lmm->lmm_objects,
                             le16_to_cpu(lmm->lmm_stripe_count));
}

void lov_dump_lmm_v3(int level, struct lov_mds_md_v3 *lmm)
{
        lov_dump_lmm_common(level, lmm);
        CDEBUG(level,"pool_name "LOV_POOLNAMEF"\n", lmm->lmm_pool_name);
        lov_dump_lmm_objects(level, lmm->lmm_objects,
                             le16_to_cpu(lmm->lmm_stripe_count));
}

void lov_dump_lmm(int level, void *lmm)
{
        int magic;

        magic = ((struct lov_mds_md_v1 *)(lmm))->lmm_magic;
        switch (magic) {
        case LOV_MAGIC_V1:
                return lov_dump_lmm_v1(level, (struct lov_mds_md_v1 *)(lmm));
        case LOV_MAGIC_V3:
                return lov_dump_lmm_v3(level, (struct lov_mds_md_v3 *)(lmm));
        default:
                CERROR("Cannot recognize lmm_magic %x", magic);
        }
        return;
}

#define LMM_ASSERT(test)                                                \
do {                                                                    \
        if (!(test)) lov_dump_lmm(D_ERROR, lmm);                        \
        LASSERT(test); /* so we know what assertion failed */           \
} while(0)

/* Pack LOV object metadata for disk storage.  It is packed in LE byte
 * order and is opaque to the networking layer.
 *
 * XXX In the future, this will be enhanced to get the EA size from the
 *     underlying OSC device(s) to get their EA sizes so we can stack
 *     LOVs properly.  For now lov_mds_md_size() just assumes one obd_id
 *     per stripe.
 */
int lov_packmd(struct obd_export *exp, struct lov_mds_md **lmmp,
               struct lov_stripe_md *lsm)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct lov_obd *lov = &obd->u.lov;
        struct lov_mds_md_v1 *lmmv1;
        struct lov_mds_md_v3 *lmmv3;
        __u16 stripe_count;
        struct lov_ost_data_v1 *lmm_objects;
        int lmm_size, lmm_magic;
        int i;
	int cplen = 0;
        ENTRY;

        if (lsm) {
                lmm_magic = lsm->lsm_magic;
        } else {
                if (lmmp && *lmmp)
                        lmm_magic = le32_to_cpu((*lmmp)->lmm_magic);
                else
                        /* lsm == NULL and lmmp == NULL */
                        lmm_magic = LOV_MAGIC;
        }

        if ((lmm_magic != LOV_MAGIC_V1) &&
            (lmm_magic != LOV_MAGIC_V3)) {
                CERROR("bad mem LOV MAGIC: 0x%08X != 0x%08X nor 0x%08X\n",
                        lmm_magic, LOV_MAGIC_V1, LOV_MAGIC_V3);
                RETURN(-EINVAL);

        }

        if (lsm) {
                /* If we are just sizing the EA, limit the stripe count
                 * to the actual number of OSTs in this filesystem. */
                if (!lmmp) {
                        stripe_count = lov_get_stripecnt(lov, lmm_magic,
                                                         lsm->lsm_stripe_count);
                        lsm->lsm_stripe_count = stripe_count;
                } else {
                        stripe_count = lsm->lsm_stripe_count;
                }
        } else {
                /* No need to allocate more than maximum supported stripes.
                 * Anyway, this is pretty inaccurate since ld_tgt_count now
                 * represents max index and we should rely on the actual number
                 * of OSTs instead */
                stripe_count = lov_mds_md_stripecnt(lov->lov_ocd.ocd_max_easize,
                                                    lmm_magic);
                if (stripe_count > lov->desc.ld_tgt_count)
                        stripe_count = lov->desc.ld_tgt_count;
        }

        /* XXX LOV STACKING call into osc for sizes */
        lmm_size = lov_mds_md_size(stripe_count, lmm_magic);

        if (!lmmp)
                RETURN(lmm_size);

        if (*lmmp && !lsm) {
                stripe_count = le16_to_cpu((*lmmp)->lmm_stripe_count);
                lmm_size = lov_mds_md_size(stripe_count, lmm_magic);
                OBD_FREE_LARGE(*lmmp, lmm_size);
                *lmmp = NULL;
                RETURN(0);
        }

        if (!*lmmp) {
                OBD_ALLOC_LARGE(*lmmp, lmm_size);
                if (!*lmmp)
                        RETURN(-ENOMEM);
        }

        CDEBUG(D_INFO, "lov_packmd: LOV_MAGIC 0x%08X, lmm_size = %d \n",
               lmm_magic, lmm_size);

        lmmv1 = *lmmp;
        lmmv3 = (struct lov_mds_md_v3 *)*lmmp;
        if (lmm_magic == LOV_MAGIC_V3)
                lmmv3->lmm_magic = cpu_to_le32(LOV_MAGIC_V3);
        else
                lmmv1->lmm_magic = cpu_to_le32(LOV_MAGIC_V1);

        if (!lsm)
                RETURN(lmm_size);

        /* lmmv1 and lmmv3 point to the same struct and have the
         * same first fields
         */
	lmm_oi_cpu_to_le(&lmmv1->lmm_oi, &lsm->lsm_oi);
        lmmv1->lmm_stripe_size = cpu_to_le32(lsm->lsm_stripe_size);
        lmmv1->lmm_stripe_count = cpu_to_le16(stripe_count);
        lmmv1->lmm_pattern = cpu_to_le32(lsm->lsm_pattern);
        lmmv1->lmm_layout_gen = cpu_to_le16(lsm->lsm_layout_gen);
        if (lsm->lsm_magic == LOV_MAGIC_V3) {
		cplen = strlcpy(lmmv3->lmm_pool_name, lsm->lsm_pool_name,
				sizeof(lmmv3->lmm_pool_name));
		if (cplen >= sizeof(lmmv3->lmm_pool_name))
			RETURN(-E2BIG);
                lmm_objects = lmmv3->lmm_objects;
        } else {
                lmm_objects = lmmv1->lmm_objects;
        }

	for (i = 0; i < stripe_count; i++) {
		struct lov_oinfo *loi = lsm->lsm_oinfo[i];
		/* XXX LOV STACKING call down to osc_packmd() to do packing */
		LASSERTF(ostid_id(&loi->loi_oi) != 0, "lmm_oi "DOSTID
			 " stripe %u/%u idx %u\n", POSTID(&lmmv1->lmm_oi),
			 i, stripe_count, loi->loi_ost_idx);
		ostid_cpu_to_le(&loi->loi_oi, &lmm_objects[i].l_ost_oi);
		lmm_objects[i].l_ost_gen = cpu_to_le32(loi->loi_ost_gen);
		lmm_objects[i].l_ost_idx = cpu_to_le32(loi->loi_ost_idx);
	}

	RETURN(lmm_size);
}

/* Find the max stripecount we should use */
__u16 lov_get_stripecnt(struct lov_obd *lov, __u32 magic, __u16 stripe_count)
{
        __u32 max_stripes = LOV_MAX_STRIPE_COUNT_OLD;

        if (!stripe_count)
                stripe_count = lov->desc.ld_default_stripe_count;
        if (stripe_count > lov->desc.ld_active_tgt_count)
                stripe_count = lov->desc.ld_active_tgt_count;
        if (!stripe_count)
                stripe_count = 1;

        /* stripe count is based on whether ldiskfs can handle
         * larger EA sizes */
        if (lov->lov_ocd.ocd_connect_flags & OBD_CONNECT_MAX_EASIZE &&
            lov->lov_ocd.ocd_max_easize)
                max_stripes = lov_mds_md_stripecnt(lov->lov_ocd.ocd_max_easize,
                                                   magic);

        if (stripe_count > max_stripes)
                stripe_count = max_stripes;

        return stripe_count;
}


static int lov_verify_lmm(void *lmm, int lmm_bytes, __u16 *stripe_count)
{
        int rc;

        if (lsm_op_find(le32_to_cpu(*(__u32 *)lmm)) == NULL) {
                char *buffer;
                int sz;

                CERROR("bad disk LOV MAGIC: 0x%08X; dumping LMM (size=%d):\n",
                       le32_to_cpu(*(__u32 *)lmm), lmm_bytes);
                sz = lmm_bytes * 2 + 1;
                OBD_ALLOC_LARGE(buffer, sz);
                if (buffer != NULL) {
                        int i;

                        for (i = 0; i < lmm_bytes; i++)
                                sprintf(buffer+2*i, "%.2X", ((char *)lmm)[i]);
			buffer[sz - 1] = '\0';
                        CERROR("%s\n", buffer);
                        OBD_FREE_LARGE(buffer, sz);
                }
                return -EINVAL;
        }
        rc = lsm_op_find(le32_to_cpu(*(__u32 *)lmm))->lsm_lmm_verify(lmm,
                                     lmm_bytes, stripe_count);
        return rc;
}

int lov_alloc_memmd(struct lov_stripe_md **lsmp, __u16 stripe_count,
                    int pattern, int magic)
{
        int i, lsm_size;
        ENTRY;

        CDEBUG(D_INFO, "alloc lsm, stripe_count %d\n", stripe_count);

        *lsmp = lsm_alloc_plain(stripe_count, &lsm_size);
        if (!*lsmp) {
                CERROR("can't allocate lsmp stripe_count %d\n", stripe_count);
                RETURN(-ENOMEM);
        }

	cfs_atomic_set(&(*lsmp)->lsm_refc, 1);
	spin_lock_init(&(*lsmp)->lsm_lock);
        (*lsmp)->lsm_magic = magic;
        (*lsmp)->lsm_stripe_count = stripe_count;
        (*lsmp)->lsm_maxbytes = LUSTRE_STRIPE_MAXBYTES * stripe_count;
        (*lsmp)->lsm_pattern = pattern;
        (*lsmp)->lsm_pool_name[0] = '\0';
        (*lsmp)->lsm_layout_gen = 0;
        (*lsmp)->lsm_oinfo[0]->loi_ost_idx = ~0;

        for (i = 0; i < stripe_count; i++)
                loi_init((*lsmp)->lsm_oinfo[i]);

        RETURN(lsm_size);
}

int lov_free_memmd(struct lov_stripe_md **lsmp)
{
	struct lov_stripe_md *lsm = *lsmp;
	int refc;

	*lsmp = NULL;
	LASSERT(cfs_atomic_read(&lsm->lsm_refc) > 0);
	if ((refc = cfs_atomic_dec_return(&lsm->lsm_refc)) == 0) {
		LASSERT(lsm_op_find(lsm->lsm_magic) != NULL);
		lsm_op_find(lsm->lsm_magic)->lsm_free(lsm);
	}
	return refc;
}


/* Unpack LOV object metadata from disk storage.  It is packed in LE byte
 * order and is opaque to the networking layer.
 */
int lov_unpackmd(struct obd_export *exp,  struct lov_stripe_md **lsmp,
                 struct lov_mds_md *lmm, int lmm_bytes)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct lov_obd *lov = &obd->u.lov;
        int rc = 0, lsm_size;
        __u16 stripe_count;
        __u32 magic;
        ENTRY;

        /* If passed an MDS struct use values from there, otherwise defaults */
        if (lmm) {
                rc = lov_verify_lmm(lmm, lmm_bytes, &stripe_count);
                if (rc)
                        RETURN(rc);
                magic = le32_to_cpu(lmm->lmm_magic);
        } else {
                magic = LOV_MAGIC;
                stripe_count = lov_get_stripecnt(lov, magic, 0);
        }

        /* If we aren't passed an lsmp struct, we just want the size */
        if (!lsmp) {
                /* XXX LOV STACKING call into osc for sizes */
                LBUG();
                RETURN(lov_stripe_md_size(stripe_count));
        }
        /* If we are passed an allocated struct but nothing to unpack, free */
        if (*lsmp && !lmm) {
                lov_free_memmd(lsmp);
                RETURN(0);
        }

        lsm_size = lov_alloc_memmd(lsmp, stripe_count, LOV_PATTERN_RAID0,
                                   magic);
        if (lsm_size < 0)
                RETURN(lsm_size);

        /* If we are passed a pointer but nothing to unpack, we only alloc */
        if (!lmm)
                RETURN(lsm_size);

        LASSERT(lsm_op_find(magic) != NULL);
        rc = lsm_op_find(magic)->lsm_unpackmd(lov, *lsmp, lmm);
        if (rc) {
                lov_free_memmd(lsmp);
                RETURN(rc);
        }

        RETURN(lsm_size);
}

static int __lov_setstripe(struct obd_export *exp, int max_lmm_size,
                           struct lov_stripe_md **lsmp,
                           struct lov_user_md *lump)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct lov_obd *lov = &obd->u.lov;
        char buffer[sizeof(struct lov_user_md_v3)];
        struct lov_user_md_v3 *lumv3 = (struct lov_user_md_v3 *)&buffer[0];
        struct lov_user_md_v1 *lumv1 = (struct lov_user_md_v1 *)&buffer[0];
        int lmm_magic;
        __u16 stripe_count;
        int rc;
	int cplen = 0;
        ENTRY;

        rc = lov_lum_swab_if_needed(lumv3, &lmm_magic, lump);
        if (rc)
                RETURN(rc);

        /* in the rest of the tests, as *lumv1 and lumv3 have the same
         * fields, we use lumv1 to avoid code duplication */

        if (lumv1->lmm_pattern == 0) {
                lumv1->lmm_pattern = lov->desc.ld_pattern ?
                        lov->desc.ld_pattern : LOV_PATTERN_RAID0;
        }

        if (lumv1->lmm_pattern != LOV_PATTERN_RAID0) {
                CDEBUG(D_IOCTL, "bad userland stripe pattern: %#x\n",
                       lumv1->lmm_pattern);
                RETURN(-EINVAL);
        }

        /* 64kB is the largest common page size we see (ia64), and matches the
         * check in lfs */
        if (lumv1->lmm_stripe_size & (LOV_MIN_STRIPE_SIZE - 1)) {
                CDEBUG(D_IOCTL, "stripe size %u not multiple of %u, fixing\n",
                       lumv1->lmm_stripe_size, LOV_MIN_STRIPE_SIZE);
                lumv1->lmm_stripe_size = LOV_MIN_STRIPE_SIZE;
        }

        if ((lumv1->lmm_stripe_offset >= lov->desc.ld_tgt_count) &&
            (lumv1->lmm_stripe_offset !=
             (typeof(lumv1->lmm_stripe_offset))(-1))) {
                CDEBUG(D_IOCTL, "stripe offset %u > number of OSTs %u\n",
                       lumv1->lmm_stripe_offset, lov->desc.ld_tgt_count);
                RETURN(-EINVAL);
        }
        stripe_count = lov_get_stripecnt(lov, lmm_magic,
                                         lumv1->lmm_stripe_count);

        if (max_lmm_size) {
                int max_stripes = (max_lmm_size -
                                   lov_mds_md_size(0, lmm_magic)) /
                                   sizeof(struct lov_ost_data_v1);
                if (unlikely(max_stripes < stripe_count)) {
                        CDEBUG(D_IOCTL, "stripe count reset from %d to %d\n",
                               stripe_count, max_stripes);
                        stripe_count = max_stripes;
                }
        }

        if (lmm_magic == LOV_USER_MAGIC_V3) {
                struct pool_desc *pool;

		/* In the function below, .hs_keycmp resolves to
		 * pool_hashkey_keycmp() */
		/* coverity[overrun-buffer-val] */
                pool = lov_find_pool(lov, lumv3->lmm_pool_name);
                if (pool != NULL) {
                        if (lumv3->lmm_stripe_offset !=
                            (typeof(lumv3->lmm_stripe_offset))(-1)) {
                                rc = lov_check_index_in_pool(
                                        lumv3->lmm_stripe_offset, pool);
                                if (rc < 0) {
                                        lov_pool_putref(pool);
                                        RETURN(-EINVAL);
                                }
                        }

                        if (stripe_count > pool_tgt_count(pool))
                                stripe_count = pool_tgt_count(pool);

                        lov_pool_putref(pool);
                }
        }

        rc = lov_alloc_memmd(lsmp, stripe_count, lumv1->lmm_pattern, lmm_magic);

        if (rc >= 0) {
                (*lsmp)->lsm_oinfo[0]->loi_ost_idx = lumv1->lmm_stripe_offset;
                (*lsmp)->lsm_stripe_size = lumv1->lmm_stripe_size;
		if (lmm_magic == LOV_USER_MAGIC_V3) {
			cplen = strlcpy((*lsmp)->lsm_pool_name,
					lumv3->lmm_pool_name,
					sizeof((*lsmp)->lsm_pool_name));
			if (cplen >= sizeof((*lsmp)->lsm_pool_name))
				rc = -E2BIG;
		}
                rc = 0;
        }

        RETURN(rc);
}

/* Configure object striping information on a new file.
 *
 * @lmmu is a pointer to a user struct with one or more of the fields set to
 * indicate the application preference: lmm_stripe_count, lmm_stripe_size,
 * lmm_stripe_offset, and lmm_stripe_pattern.  lmm_magic must be LOV_MAGIC.
 * @lsmp is a pointer to an in-core stripe MD that needs to be filled in.
 */
int lov_setstripe(struct obd_export *exp, int max_lmm_size,
                  struct lov_stripe_md **lsmp, struct lov_user_md *lump)
{
        int rc;
        mm_segment_t seg;

        seg = get_fs();
        set_fs(KERNEL_DS);

        rc = __lov_setstripe(exp, max_lmm_size, lsmp, lump);
        set_fs(seg);
        RETURN(rc);
}

int lov_setea(struct obd_export *exp, struct lov_stripe_md **lsmp,
              struct lov_user_md *lump)
{
        int i;
        int rc;
        struct obd_export *oexp;
        struct lov_obd *lov = &exp->exp_obd->u.lov;
        obd_id last_id = 0;
        struct lov_user_ost_data_v1 *lmm_objects;

        ENTRY;

        if (lump->lmm_magic == LOV_USER_MAGIC_V3)
                lmm_objects = ((struct lov_user_md_v3 *)lump)->lmm_objects;
        else
                lmm_objects = lump->lmm_objects;

        for (i = 0; i < lump->lmm_stripe_count; i++) {
                __u32 len = sizeof(last_id);
                oexp = lov->lov_tgts[lmm_objects[i].l_ost_idx]->ltd_exp;
                rc = obd_get_info(NULL, oexp, sizeof(KEY_LAST_ID), KEY_LAST_ID,
                                  &len, &last_id, NULL);
                if (rc)
                        RETURN(rc);
		if (ostid_id(&lmm_objects[i].l_ost_oi) > last_id) {
			CERROR("Setting EA for object > than last id on"
			       " ost idx %d "DOSTID" > "LPD64" \n",
			       lmm_objects[i].l_ost_idx,
			       POSTID(&lmm_objects[i].l_ost_oi), last_id);
			RETURN(-EINVAL);
		}
        }

        rc = lov_setstripe(exp, 0, lsmp, lump);
        if (rc)
                RETURN(rc);

        for (i = 0; i < lump->lmm_stripe_count; i++) {
                (*lsmp)->lsm_oinfo[i]->loi_ost_idx =
                        lmm_objects[i].l_ost_idx;
		(*lsmp)->lsm_oinfo[i]->loi_oi = lmm_objects[i].l_ost_oi;
        }
        RETURN(0);
}


/* Retrieve object striping information.
 *
 * @lump is a pointer to an in-core struct with lmm_ost_count indicating
 * the maximum number of OST indices which will fit in the user buffer.
 * lmm_magic must be LOV_USER_MAGIC.
 */
int lov_getstripe(struct obd_export *exp, struct lov_stripe_md *lsm,
                  struct lov_user_md *lump)
{
        /*
         * XXX huge struct allocated on stack.
         */
        /* we use lov_user_md_v3 because it is larger than lov_user_md_v1 */
        struct lov_user_md_v3 lum;
        struct lov_mds_md *lmmk = NULL;
        int rc, lmm_size;
        int lum_size;
        mm_segment_t seg;
        ENTRY;

        if (!lsm)
                RETURN(-ENODATA);

        /*
         * "Switch to kernel segment" to allow copying from kernel space by
         * copy_{to,from}_user().
         */
        seg = get_fs();
        set_fs(KERNEL_DS);

        /* we only need the header part from user space to get lmm_magic and
         * lmm_stripe_count, (the header part is common to v1 and v3) */
        lum_size = sizeof(struct lov_user_md_v1);
        if (cfs_copy_from_user(&lum, lump, lum_size))
                GOTO(out_set, rc = -EFAULT);
        else if ((lum.lmm_magic != LOV_USER_MAGIC) &&
                 (lum.lmm_magic != LOV_USER_MAGIC_V3))
                GOTO(out_set, rc = -EINVAL);

        if (lum.lmm_stripe_count &&
            (lum.lmm_stripe_count < lsm->lsm_stripe_count)) {
                /* Return right size of stripe to user */
                lum.lmm_stripe_count = lsm->lsm_stripe_count;
                rc = cfs_copy_to_user(lump, &lum, lum_size);
                GOTO(out_set, rc = -EOVERFLOW);
        }
        rc = lov_packmd(exp, &lmmk, lsm);
        if (rc < 0)
                GOTO(out_set, rc);
        lmm_size = rc;
        rc = 0;

        /* FIXME: Bug 1185 - copy fields properly when structs change */
        /* struct lov_user_md_v3 and struct lov_mds_md_v3 must be the same */
        CLASSERT(sizeof(lum) == sizeof(struct lov_mds_md_v3));
        CLASSERT(sizeof lum.lmm_objects[0] == sizeof lmmk->lmm_objects[0]);

        if ((cpu_to_le32(LOV_MAGIC) != LOV_MAGIC) &&
            ((lmmk->lmm_magic == cpu_to_le32(LOV_MAGIC_V1)) ||
            (lmmk->lmm_magic == cpu_to_le32(LOV_MAGIC_V3)))) {
                lustre_swab_lov_mds_md(lmmk);
                lustre_swab_lov_user_md_objects(
                                (struct lov_user_ost_data*)lmmk->lmm_objects,
                                lmmk->lmm_stripe_count);
        }
        if (lum.lmm_magic == LOV_USER_MAGIC) {
                /* User request for v1, we need skip lmm_pool_name */
                if (lmmk->lmm_magic == LOV_MAGIC_V3) {
                        memmove((char*)(&lmmk->lmm_stripe_count) +
                                sizeof(lmmk->lmm_stripe_count),
                                ((struct lov_mds_md_v3*)lmmk)->lmm_objects,
                                lmmk->lmm_stripe_count *
                                sizeof(struct lov_ost_data_v1));
                        lmm_size -= LOV_MAXPOOLNAME;
                }
        } else {
                /* if v3 we just have to update the lum_size */
                lum_size = sizeof(struct lov_user_md_v3);
        }

        /* User wasn't expecting this many OST entries */
        if (lum.lmm_stripe_count == 0)
                lmm_size = lum_size;
        else if (lum.lmm_stripe_count < lmmk->lmm_stripe_count)
                GOTO(out_set, rc = -EOVERFLOW);
	/*
	 * Have a difference between lov_mds_md & lov_user_md.
	 * So we have to re-order the data before copy to user.
	 */
	lum.lmm_stripe_count = lmmk->lmm_stripe_count;
	lum.lmm_layout_gen = lmmk->lmm_layout_gen;
	((struct lov_user_md *)lmmk)->lmm_layout_gen = lum.lmm_layout_gen;
	((struct lov_user_md *)lmmk)->lmm_stripe_count = lum.lmm_stripe_count;
	if (cfs_copy_to_user(lump, lmmk, lmm_size))
		rc = -EFAULT;

	obd_free_diskmd(exp, &lmmk);
out_set:
	set_fs(seg);
	RETURN(rc);
}
