/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lib/simple.c
 *
 * Copyright (C) 2002  Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 *
 * by Peter Braam <braam@clusterfs.com>
 * and Andreas Dilger <adilger@clusterfs.com>
 */

#define EXPORT_SYMTAB

#include <linux/version.h>
#include <linux/fs.h>
#include <asm/unistd.h>

#define DEBUG_SUBSYSTEM S_FILTER

#include <linux/obd_support.h>
#include <linux/obd.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_net.h>

#ifdef OBD_CTXT_DEBUG
/* Debugging check only needed during development */
#define ASSERT_CTXT_MAGIC(magic) LASSERT((magic) == OBD_RUN_CTXT_MAGIC)
#define ASSERT_NOT_KERNEL_CTXT(msg) LASSERT(!segment_eq(get_fs(), get_ds()))
#define ASSERT_KERNEL_CTXT(msg) LASSERT(segment_eq(get_fs(), get_ds()))
#else
#define ASSERT_CTXT_MAGIC(magic) do {} while(0)
#define ASSERT_NOT_KERNEL_CTXT(msg) do {} while(0)
#define ASSERT_KERNEL_CTXT(msg) do {} while(0)
#endif

/* push / pop to root of obd store */
void push_ctxt(struct obd_run_ctxt *save, struct obd_run_ctxt *new_ctx,
               struct obd_ucred *uc)
{
        //ASSERT_NOT_KERNEL_CTXT("already in kernel context!\n");
        ASSERT_CTXT_MAGIC(new_ctx->magic);
        OBD_SET_CTXT_MAGIC(save);

        /*
        CDEBUG(D_INFO, "== push %p->%p == cur fs %p pwd %p (%*s), pwdmnt %p\n",
               save, current, current->fs, current->fs->pwd,
               current->fs->pwd->d_name.len, current->fs->pwd->d_name.name,
               current->fs->pwdmnt);
        */

        save->fs = get_fs();
        LASSERT(atomic_read(&current->fs->pwd->d_count));
        LASSERT(atomic_read(&new_ctx->pwd->d_count));
        save->pwd = dget(current->fs->pwd);
        save->pwdmnt = mntget(current->fs->pwdmnt);

        LASSERT(save->pwd);
        LASSERT(save->pwdmnt);
        LASSERT(new_ctx->pwd);
        LASSERT(new_ctx->pwdmnt);

        if (uc) {
                save->fsuid = current->fsuid;
                save->fsgid = current->fsgid;
                save->cap = current->cap_effective;

                current->fsuid = uc->ouc_fsuid;
                current->fsgid = uc->ouc_fsgid;
                current->cap_effective = uc->ouc_cap;
        }
        set_fs(new_ctx->fs);
        set_fs_pwd(current->fs, new_ctx->pwdmnt, new_ctx->pwd);

        /*
        CDEBUG(D_INFO, "== push %p==%p == cur fs %p pwd %p (%*s), pwdmnt %p\n",
               new_ctx, current, current->fs, current->fs->pwd,
               current->fs->pwd->d_name.len, current->fs->pwd->d_name.name,
               current->fs->pwdmnt);
        */
}

void pop_ctxt(struct obd_run_ctxt *saved, struct obd_run_ctxt *new_ctx,
              struct obd_ucred *uc)
{
        //printk("pc0");
        ASSERT_CTXT_MAGIC(saved->magic);
        //printk("pc1");
        ASSERT_KERNEL_CTXT("popping non-kernel context!\n");

        /*
        CDEBUG(D_INFO, " == pop  %p==%p == cur %p pwd %p (%*s), pwdmnt %p\n",
               new_ctx, current, current->fs, current->fs->pwd,
               current->fs->pwd->d_name.len, current->fs->pwd->d_name.name,
               current->fs->pwdmnt);
        */

        LASSERT(current->fs->pwd == new_ctx->pwd);
        LASSERT(current->fs->pwdmnt == new_ctx->pwdmnt);

        //printk("pc2");
        set_fs(saved->fs);
        //printk("pc3\n");
        set_fs_pwd(current->fs, saved->pwdmnt, saved->pwd);
        //printk("pc4");

        dput(saved->pwd);
        //printk("pc5");
        mntput(saved->pwdmnt);
        //printk("pc6\n");
        if (uc) {
                current->fsuid = saved->fsuid;
                current->fsgid = saved->fsgid;
                current->cap_effective = saved->cap;
        }

        /*
        CDEBUG(D_INFO, "== pop  %p->%p == cur fs %p pwd %p (%*s), pwdmnt %p\n",
               saved, current, current->fs, current->fs->pwd,
               current->fs->pwd->d_name.len, current->fs->pwd->d_name.name,
               current->fs->pwdmnt);
        */
}

/* utility to make a file */
struct dentry *simple_mknod(struct dentry *dir, char *name, int mode)
{
        struct dentry *dchild;
        int err = 0;
        ENTRY;

        ASSERT_KERNEL_CTXT("kernel doing mknod outside kernel context\n");
        CDEBUG(D_INODE, "creating file %*s\n", (int)strlen(name), name);

        down(&dir->d_inode->i_sem);
        dchild = lookup_one_len(name, dir, strlen(name));
        if (IS_ERR(dchild))
                GOTO(out_up, dchild);

        if (dchild->d_inode) {
                if ((dchild->d_inode->i_mode & S_IFMT) != S_IFREG)
                        GOTO(out_err, err = -EEXIST);

                GOTO(out_up, dchild);
        }

        err = vfs_create(dir->d_inode, dchild, (mode & ~S_IFMT) | S_IFREG);
        if (err)
                GOTO(out_err, err);

        up(&dir->d_inode->i_sem);
        RETURN(dchild);

out_err:
        dput(dchild);
        dchild = ERR_PTR(err);
out_up:
        up(&dir->d_inode->i_sem);
        return dchild;
}

/* utility to make a directory */
struct dentry *simple_mkdir(struct dentry *dir, char *name, int mode)
{
        struct dentry *dchild;
        int err = 0;
        ENTRY;

        ASSERT_KERNEL_CTXT("kernel doing mkdir outside kernel context\n");
        CDEBUG(D_INODE, "creating directory %*s\n", (int)strlen(name), name);
        down(&dir->d_inode->i_sem);
        dchild = lookup_one_len(name, dir, strlen(name));
        if (IS_ERR(dchild))
                GOTO(out_up, dchild);

        if (dchild->d_inode) {
                if (!S_ISDIR(dchild->d_inode->i_mode))
                        GOTO(out_err, err = -ENOTDIR);

                GOTO(out_up, dchild);
        }

        err = vfs_mkdir(dir->d_inode, dchild, mode);
        if (err)
                GOTO(out_err, err);

        up(&dir->d_inode->i_sem);
        RETURN(dchild);

out_err:
        dput(dchild);
        dchild = ERR_PTR(err);
out_up:
        up(&dir->d_inode->i_sem);
        return dchild;
}

/*
 * Read a file from within kernel context.  Prior to calling this
 * function we should already have done a push_ctxt().
 */
int lustre_fread(struct file *file, char *str, int len, loff_t *off)
{
        ASSERT_KERNEL_CTXT("kernel doing read outside kernel context\n");
        if (!file || !file->f_op || !file->f_op->read || !off)
                RETURN(-ENOSYS);

        return file->f_op->read(file, str, len, off);
}

/*
 * Write a file from within kernel context.  Prior to calling this
 * function we should already have done a push_ctxt().
 */
int lustre_fwrite(struct file *file, const char *str, int len, loff_t *off)
{
        ENTRY;
        ASSERT_KERNEL_CTXT("kernel doing write outside kernel context\n");
        if (!file)
                RETURN(-ENOENT);
        if (!file->f_op)
                RETURN(-ENOSYS);
        if (!off)
                RETURN(-EINVAL);

        if (!file->f_op->write)
                RETURN(-EROFS);

        RETURN(file->f_op->write(file, str, len, off));
}

/*
 * Sync a file from within kernel context.  Prior to calling this
 * function we should already have done a push_ctxt().
 */
int lustre_fsync(struct file *file)
{
        ENTRY;
        ASSERT_KERNEL_CTXT("kernel doing sync outside kernel context\n");
        if (!file || !file->f_op || !file->f_op->fsync)
                RETURN(-ENOSYS);

        RETURN(file->f_op->fsync(file, file->f_dentry, 0));
}
