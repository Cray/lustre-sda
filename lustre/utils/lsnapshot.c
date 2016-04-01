/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.  A copy is
 * included in the COPYING file that accompanied this code.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2015, Intel Corporation.
 *
 * lustre/utils/lsnapshot.c
 *
 * Author: Fan, Yong <fan.yong@intel.com>
 */

#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/file.h>
#include <time.h>

#include <lustre/lustre_barrier_user.h>
#include <libcfs/list.h>

#include "obdctl.h"

#define SNAPSHOT_CONF_DIR	"/etc/lsnapshot"
#define SNAPSHOT_LOG		"/var/log/lsnapshot.log"
#define SNAPSHOT_MAGIC		"0x14F711B9"

enum snapshot_role {
	SR_MGS	= 0x0001,
	SR_MDT	= 0x0002,
	SR_OST	= 0x0004,
};

struct snapshot_target {
	struct list_head	 st_list;
	/* Target node name. */
	char			*st_host;
	/* Where the pool is */
	char			*st_dir;
	/* The target pool name on the target node. */
	char			*st_pool;
	/* The backend filesystem name against the target pool. */
	char			*st_filesystem;
	int			 st_role;
	unsigned int		 st_index;
	unsigned int		 st_gen;
	int			 st_line;
	int			 st_status;
	pid_t			 st_pid;
	bool			 st_ignored;
};

struct snapshot_instance {
	struct list_head	 si_mdts_list;
	struct list_head	 si_osts_list;
	struct snapshot_target	*si_mgs;
	struct snapshot_target	*si_mdt0;
	FILE			*si_log_fp;
	char			*si_rsh;
	char			*si_fsname;
	char			*si_ssname;
	char			*si_new_ssname;
	char			*si_comment;
	int			 si_conf_fd;
	int			 si_timeout;
	bool			 si_barrier;
	bool			 si_detail;
	bool			 si_force;
};

static char snapshot_rsh_default[] = "ssh";

static char *snapshot_role2name(char *name, enum snapshot_role role,
				__u32 index)
{
	if (role & SR_MDT)
		sprintf(name, "MDT%04x", index);
	else if (role & SR_MGS)
		sprintf(name, "MGS");
	else
		sprintf(name, "OST%04x", index);

	return name;
}

#define SNAPSHOT_ADD_LOG(si, format, ...)				\
do {									\
	char buf[PAGE_SIZE];						\
	char *ptr;							\
	time_t tt;							\
									\
	memset(buf, 0, sizeof(buf));					\
	time(&tt);							\
	snprintf(buf, sizeof(buf) - 1, "%s", ctime(&tt));		\
	ptr = strrchr(buf, '\n');					\
	if (likely(ptr != NULL))					\
		*ptr = '\0';						\
									\
	fprintf(si->si_log_fp, "%s (%d:%s:%d:%s:%s): "format, buf,	\
		getpid(), __FUNCTION__, __LINE__, si->si_fsname,	\
		si->si_rsh, ## __VA_ARGS__);				\
} while (0)

char *snapshot_fgets(FILE *fp, char *buf, int buflen)
{
	char *ptr;

	memset(buf, 0, buflen);
	if (fgets(buf, buflen, fp) == NULL)
		return NULL;

	ptr = strchr(buf, '\n');
	if (ptr != NULL)
		*ptr = '\0';

	return buf;
}

static int snapshot_exec(const char *cmd)
{
	int rc;

	errno = 0;

	/* system() return value depends on both the system() general framework,
	 * such as whether fork()/exec() success or fail, and the real @cmd exec
	 * result. Especially, if the @cmd is remote command, we may cannot know
	 * the real failure. */
	rc = system(cmd);
	/* fork()/exec() error */
	if (rc == -1)
		return errno != 0 ? -errno : -1;

	if (WIFEXITED(rc)) {
		rc = WEXITSTATUS(rc);
		if (rc > 0)
			rc = -rc;
	} else if (WIFSIGNALED(rc)) {
		rc = -EINTR;
	} else {
		/* all other known or unknown cases. */
		rc = -EFAULT;
	}

	return rc;
}

/* The format is:
 * <host> <pool_dir> <pool> <local_fsname> <role(,s)> <index>
 *
 * For example:
 *
 * RHEL6 /tmp lustre-mdt1 mdt1 MGS,MDT 0
 * RHEL6 /tmp lustre-mdt2 mdt2 MDT 1
 * RHEL6 /tmp lustre-ost1 ost1 OST 0
 * RHEL6 /tmp lustre-ost2 ost2 OST 1
 *
 * We do use scanf() family functions for parsing because that they may cause
 * buffer overflow if the given input is too large, even if we specify "%ns",
 * the left part(s) will be assigned to the next item unexpectedly. Sometime,
 * such trouble cannot be detected in time, then cause some strange behaviour.
 *
 * \retval	0 for success
 * \retval	+ve the line# with which the current line is conflict
 * \retval	-ve other failures
 */
static int snapshot_load_conf_one(struct snapshot_instance *si,
				  char *buf, int line_num)
{
	struct snapshot_target *st;
	char *role = NULL;
	int rc = 0;

	st = malloc(sizeof(*st));
	if (st == NULL)
		return -ENOMEM;

	memset(st, 0, sizeof(*st));
	INIT_LIST_HEAD(&st->st_list);

	rc = sscanf(buf, "%ms %ms %ms %ms %ms %d",
		    &st->st_host, &st->st_dir, &st->st_pool, &st->st_filesystem,
		    &role, &st->st_index);
	if (rc < 6) {
		rc = -EINVAL;
		goto out;
	}

	rc = 0;

	if (strncasecmp(role, "MGS", 3) == 0) {
		st->st_role = SR_MGS;
		if (role[3] == ',') {
			/* MGS,MDT */
			if (strncasecmp(&role[4], "MDT", 3) != 0) {
				rc = -EINVAL;
				goto out;
			}

			st->st_role |= SR_MDT;
		}
	} else if (strncasecmp(role, "MDT", 3) == 0) {
		st->st_role = SR_MDT;
		if (role[3] == ',') {
			/* MDT,MGS */
			if (strncasecmp(&role[4], "MGS", 3) != 0) {
				rc = -EINVAL;
				goto out;
			}

			st->st_role |= SR_MGS;
		}
	} else if (strncasecmp(role, "OST", 3) == 0) {
		st->st_role = SR_OST;
	} else {
		rc = -EINVAL;
		goto out;
	}

	st->st_line = line_num;
	if (st->st_role & SR_MDT) {
		/* MGS is the first, MDT0 is just after the MGS
		 * if they are not combined together. */
		if (st->st_role & SR_MGS) {
			if (si->si_mgs != NULL) {
				rc = si->si_mgs->st_line;
				goto out;
			}

			si->si_mgs = st;
			list_add(&st->st_list, &si->si_mdts_list);
		}

		if (st->st_index == 0) {
			if (si->si_mdt0 != NULL) {
				rc = si->si_mdt0->st_line;
				goto out;
			}

			si->si_mdt0 = st;
			if (list_empty(&st->st_list)) {
				if (list_empty(&si->si_mdts_list) ||
				    si->si_mgs == NULL)
					list_add(&st->st_list,
						 &si->si_mdts_list);
				else
					list_add(&st->st_list,
						 &si->si_mgs->st_list);
			}
		} else if (list_empty(&st->st_list)) {
			list_add_tail(&st->st_list, &si->si_mdts_list);
		}
	} else if (st->st_role & SR_MGS) {
		if (si->si_mgs != NULL) {
			rc = si->si_mgs->st_line;
			goto out;
		}

		si->si_mgs = st;
		list_add(&st->st_list, &si->si_mdts_list);
	} else {
		list_add_tail(&st->st_list, &si->si_osts_list);
	}

out:
	if (role != NULL)
		free(role);

	if (rc != 0) {
		if (st->st_host != NULL)
			free(st->st_host);
		if (st->st_dir != NULL)
			free(st->st_dir);
		if (st->st_pool != NULL)
			free(st->st_pool);
		if (st->st_filesystem != NULL)
			free(st->st_filesystem);
		free(st);
	}

	return rc;
}

static int snapshot_load_conf(struct snapshot_instance *si, int lock_mode)
{
	FILE *fp;
	char buf[PAGE_SIZE];
	char conf_name[32];
	int line_num = 1;
	int fd = -1;
	int rc = 0;

	memset(conf_name, 0, sizeof(conf_name));
	snprintf(conf_name, sizeof(conf_name) - 1, "%s/%s.conf",
		 SNAPSHOT_CONF_DIR, si->si_fsname);

	fd = open(conf_name, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr,
			"Can't open the snapshot config file %s: %s\n",
			conf_name, strerror(errno));
		return fd;
	}

	rc = flock(fd, lock_mode | LOCK_NB);
	if (rc < 0) {
		fprintf(stderr,
			"Can't lock the snapshot config file %s (%d): %s\n",
			conf_name, lock_mode, strerror(errno));
		close(fd);
		return rc;
	}

	fp = fdopen(fd, "r");
	if (fp == NULL) {
		fprintf(stderr,
			"Can't fdopen the snapshot config file %s: %s\n",
			conf_name, strerror(errno));
		rc = -1;
		goto out;
	}

	while (fgets(buf, PAGE_SIZE, fp) != NULL) {
		rc = snapshot_load_conf_one(si, buf, line_num);
		if (rc == -EINVAL) {
			fprintf(stderr,
				"Invalid snapshot config file %s at the line "
				"%d '%s'. The right format should be:\n"
				"host_name\tpool_dir\tpool_name\t"
				"local_filesystem_name\trole(,s)\tindex\n",
				conf_name, line_num, buf);
		} else if (rc > 0) {
			fprintf(stderr,
				"The config role has been specified repeatedly "
				"at the lines %d/%d in %s\n",
				rc, line_num, conf_name);
			rc = -EINVAL;
		}

		if (rc != 0)
			goto out;

		line_num++;
	}

	if (si->si_mgs == NULL) {
		fprintf(stderr,
			"Miss MGS in the config file %s\n",
			conf_name);
		rc = -1;
		goto out;
	}

	if (si->si_mdt0 == NULL) {
		fprintf(stderr,
			"Miss MDT0 in the config file %s\n",
			conf_name);
		rc = -1;
		goto out;
	}

	if (list_empty(&si->si_osts_list)) {
		fprintf(stderr,
			"Miss OST(s) in the config file %s\n",
			conf_name);
		rc = -1;
		goto out;
	}

out:
	if(fd >= 0) {
		if (rc < 0) {
			flock(fd, LOCK_UN);
			close(fd);
		} else {
			si->si_conf_fd = fd;
		}
	}

	return rc;
}

static void snapshot_unload_conf(struct snapshot_instance *si)
{
	while (!list_empty(&si->si_mdts_list)) {
		struct snapshot_target *st =
			list_entry(si->si_mdts_list.next,
				   struct snapshot_target, st_list);

		list_del(&st->st_list);
		free(st->st_host);
		free(st->st_dir);
		free(st->st_pool);
		free(st->st_filesystem);
		free(st);
	}

	while (!list_empty(&si->si_osts_list)) {
		struct snapshot_target *st =
			list_entry(si->si_osts_list.next,
				   struct snapshot_target, st_list);

		list_del(&st->st_list);
		free(st->st_host);
		free(st->st_dir);
		free(st->st_pool);
		free(st->st_filesystem);
		free(st);
	}

	si->si_mgs = NULL;
	si->si_mdt0 = NULL;

	if (si->si_conf_fd >= 0) {
		flock(si->si_conf_fd, LOCK_UN);
		close(si->si_conf_fd);
		si->si_conf_fd = -1;
	}
}

static int snapshot_handle_string_option(char **dst, const char *option,
					 const char *opt_name)
{
	if (*dst != NULL && *dst != snapshot_rsh_default) {
		fprintf(stderr, "specify the %s repeatedly.\n", opt_name);
		return -EINVAL;
	}

	*dst = malloc(strlen(option) + 1);
	if (*dst == NULL)
		return -ENOMEM;

	strcpy(*dst, option);
	return 0;
}

static void snapshot_fini(struct snapshot_instance *si)
{
	snapshot_unload_conf(si);

	if (si->si_log_fp != NULL)
		fclose(si->si_log_fp);

	if (si->si_rsh != NULL && si->si_rsh != snapshot_rsh_default)
		free(si->si_rsh);
	if (si->si_fsname != NULL)
		free(si->si_fsname);
	if (si->si_ssname != NULL)
		free(si->si_ssname);
	if (si->si_new_ssname != NULL)
		free(si->si_new_ssname);
	if (si->si_comment != NULL)
		free(si->si_comment);

	free(si);
}

static struct snapshot_instance *
snapshot_init(int argc, char * const argv[], const struct option *longopts,
	      const char *optstring, void (*usage)(void),
	      int lock_mode, int *err)
{
	struct snapshot_instance *si;
	int idx;
	int opt;

	*err = 0;
	si = malloc(sizeof(*si));
	if (si == NULL) {
		fprintf(stderr,
			"No enough memory to initialize snapshot instance.\n");
		*err = -ENOMEM;
		return NULL;
	}

	memset(si, 0, sizeof(*si));
	INIT_LIST_HEAD(&si->si_mdts_list);
	INIT_LIST_HEAD(&si->si_osts_list);
	si->si_rsh = snapshot_rsh_default;
	si->si_conf_fd = -1;
	si->si_timeout = BARRIER_TIMEOUT_DEFAULT;
	si->si_barrier = true;
	si->si_detail = false;
	si->si_force = false;

	while ((opt = getopt_long(argc, argv, optstring,
				  longopts, &idx)) != EOF) {
		switch (opt) {
		case 'b':
			if (optarg == NULL ||
			    strcmp(optarg, "on") == 0) {
				si->si_barrier = true;
			} else if (strcmp(optarg, "off") == 0) {
				si->si_barrier = false;
			} else {
				usage();
				*err = -EINVAL;
				goto out;
			}
			break;
		case 'c':
			*err = snapshot_handle_string_option(&si->si_comment,
							     optarg, "comment");
			if (*err != 0)
				goto out;
			break;
		case 'd':
			si->si_detail = true;
			break;
		case 'f':
			si->si_force = true;
			break;
		case 'F':
			*err = snapshot_handle_string_option(&si->si_fsname,
							     optarg, "fsname");
			if (*err != 0)
				goto out;
			break;
		case 'n':
			*err = snapshot_handle_string_option(&si->si_ssname,
							     optarg, "ssname");
			if (*err != 0)
				goto out;
			break;
		case 'N':
			*err = snapshot_handle_string_option(&si->si_new_ssname,
							     optarg,
							     "new ssname");
			if (*err != 0)
				goto out;
			break;
		case 'r':
			*err = snapshot_handle_string_option(&si->si_rsh,
							     optarg,
							     "remote shell");
			if (*err != 0)
				goto out;
			break;
		case 't':
			si->si_timeout = atoi(optarg);
			break;
		default:
			*err = -EINVAL;
			usage();
			goto out;
		case 'h':
			usage();
			snapshot_fini(si);
			*err = 0;
			return NULL;
		}
	}

	if (si->si_fsname == NULL) {
		fprintf(stderr, "The fsname must be specified\n");
		usage();
		*err = -EINVAL;
		goto out;
	}

	if (strlen(si->si_fsname) > 8) {
		fprintf(stderr, "Invalid fsname %s\n", si->si_fsname);
		*err = -EINVAL;
		goto out;
	}

	si->si_log_fp = fopen(SNAPSHOT_LOG, "a");
	if (si->si_log_fp == NULL) {
		*err = -errno;
		fprintf(stderr,
			"Can't open the snapshot log file %s: %s\n",
			SNAPSHOT_LOG, strerror(errno));
		goto out;
	}

	*err = snapshot_load_conf(si, lock_mode);

out:
	if (*err != 0 && si != NULL) {
		snapshot_fini(si);
		si = NULL;
	}

	return si;
}

static int __snapshot_wait(struct snapshot_instance *si,
			   struct list_head *head, int *err)
{
	struct snapshot_target *st;
	int count = 0;
	int rc = 0;

	list_for_each_entry(st, head, st_list) {
		if (st->st_pid == 0)
			continue;

		rc = waitpid(st->st_pid, &st->st_status, 0);
		if (rc < 0) {
			SNAPSHOT_ADD_LOG(si, "Can't wait child (%d) operation "
					 "on the target <%s:%x:%d>: %s\n",
					 st->st_pid, st->st_host, st->st_role,
					 st->st_index, strerror(errno));
			count++;
			if (*err == 0)
				*err = rc;

			st->st_pid = 0;
			/* continue to wait for next */
			continue;
		}

		if (WIFEXITED(st->st_status)) {
			rc = WEXITSTATUS(st->st_status);
			if(rc > 0)
				rc -= 256;

			if (unlikely(rc == -ESRCH)) {
				st->st_ignored = true;
			} else if (rc != 0) {
				count++;
				if (*err == 0)
					*err = rc;
			}
		} else if (WIFSIGNALED(st->st_status)) {
			SNAPSHOT_ADD_LOG(si, "The child (%d) operation on the "
					 "target <%s:%x:%d> was killed by "
					 "signal %d\n",
					 st->st_pid, st->st_host, st->st_role,
					 st->st_index, WTERMSIG(st->st_status));
			count++;
			if (*err == 0)
				*err = -EINTR;
		} else {
			SNAPSHOT_ADD_LOG(si, "The child (%d) operation on the "
					 "target <%s:%x:%d> failed for "
					 "unknown reason\n",
					 st->st_pid, st->st_host, st->st_role,
					 st->st_index);
			count++;
			if (*err == 0)
				*err = -EFAULT;
		}

		st->st_pid = 0;
	}

	return count;
}

static int snapshot_wait(struct snapshot_instance *si, int *err)
{
	int count;

	count = __snapshot_wait(si, &si->si_mdts_list, err);
	count += __snapshot_wait(si, &si->si_osts_list, err);

	return count;
}

static int mdt0_is_lustre_snapshot(struct snapshot_instance *si)
{
	char buf[PAGE_SIZE];
	FILE *fp;
	int rc;

	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf) - 1,
		 "%s %s 'zpool import -d %s %s > /dev/null 2>&1; "
		 "zfs get -H -o value lustre:magic %s/%s@%s'",
		 si->si_rsh, si->si_mdt0->st_host, si->si_mdt0->st_dir,
		 si->si_mdt0->st_pool, si->si_mdt0->st_pool,
		 si->si_mdt0->st_filesystem, si->si_ssname);
	fp = popen(buf, "r");
	if (fp == NULL) {
		SNAPSHOT_ADD_LOG(si, "Popen fail to check snapshot "
				 "on mdt0: %s\n", strerror(errno));
		return -errno;
	}

	if (snapshot_fgets(fp, buf, strlen(SNAPSHOT_MAGIC) + 1) == NULL) {
		rc = -EINVAL;
	} else if (strcmp(buf, SNAPSHOT_MAGIC) == 0) {
		rc = 0;
	} else {
		fprintf(stderr,
			"The target %s is not Lustre snapshot "
			"or it does not exists\n", si->si_ssname);
		rc = -EPERM;
	}

	pclose(fp);
	return rc;
}

static int target_is_mounted(struct snapshot_instance *si,
			     struct snapshot_target *st, const char *ssname)
{
	char buf[PAGE_SIZE];
	char fullname[PAGE_SIZE];
	FILE *fp;
	char *ptr;
	int rc = 0;

	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf) - 1, "%s %s 'mount'",
		 si->si_rsh, st->st_host);
	fp = popen(buf, "r");
	if (fp == NULL) {
		SNAPSHOT_ADD_LOG(si, "Popen fail to check target mount: %s\n",
				 strerror(errno));
		return -errno;
	}

	memset(fullname, 0, sizeof(fullname));
	if (ssname != NULL)
		snprintf(fullname, sizeof(fullname) - 1, "%s/%s@%s on ",
			 st->st_pool, st->st_filesystem, ssname);
	else
		snprintf(fullname, sizeof(fullname) - 1, "%s/%s on ",
			 st->st_pool, st->st_filesystem);

	while (snapshot_fgets(fp, buf, sizeof(buf)) != NULL) {
		ptr = strstr(buf, fullname);
		if (ptr == NULL)
			continue;

		ptr += strlen(fullname) + 1; /* mount point */
		if (ptr >= buf + strlen(buf))
			continue;

		ptr = strstr(ptr, "type lustre");
		if (ptr != NULL) {
			rc = 1;
			break;
		}
	}

	pclose(fp);
	return rc;
}

static int snapshot_get_fsname(struct snapshot_instance *si,
			       char *fsname, int fslen)
{
	char buf[PAGE_SIZE];
	FILE *fp;
	int rc = 0;

	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf) - 1,
		 "%s %s 'zpool import -d %s %s > /dev/null 2>&1; "
		 "zfs get -H -o value lustre:fsname %s/%s@%s'",
		 si->si_rsh, si->si_mdt0->st_host, si->si_mdt0->st_dir,
		 si->si_mdt0->st_pool, si->si_mdt0->st_pool,
		 si->si_mdt0->st_filesystem, si->si_ssname);
	fp = popen(buf, "r");
	if (fp == NULL) {
		SNAPSHOT_ADD_LOG(si, "Popen fail to get fsname: %s\n",
				 strerror(errno));
		return -errno;
	}

	if (snapshot_fgets(fp, fsname, fslen) == NULL)
		rc = -EINVAL;

	pclose(fp);
	return rc;
}

static int snapshot_get_mgsnode(struct snapshot_instance *si,
				char *node, int size)
{
	char buf[PAGE_SIZE];
	struct snapshot_target *st;
	FILE *fp;
	int rc = 0;

	st = list_entry(si->si_osts_list.next, struct snapshot_target,
			st_list);
	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf) - 1,
		 "%s %s 'zfs get -H -o value lustre:mgsnode %s/%s'",
		 si->si_rsh, st->st_host, st->st_pool, st->st_filesystem);
	fp = popen(buf, "r");
	if (fp == NULL) {
		SNAPSHOT_ADD_LOG(si, "Popen fail to get mgsnode: %s\n",
				 strerror(errno));
		return -errno;
	}

	if (snapshot_fgets(fp, node, size) == NULL)
		rc = -EINVAL;

	pclose(fp);
	return rc;
}

static int snapshot_general_check(struct snapshot_instance *si)
{
	return mdt0_is_lustre_snapshot(si);
}

static void snapshot_create_usage(void)
{
	fprintf(stderr,
		"Create snapshot for the given filesystem.\n"
		"Usage:\n"
		"snapshot_create [-b | --barrier [on | off]] "
				"[-c | --comment comment] "
				"<-F | --fsname fsname] "
				"[-h | --help] <-n | --name ssname> "
				"[-r | --rsh remote_shell]"
				"[-t | --timeout timeout]\n"
		"Options:\n"
		"-b: set write barrier before creating snapshot, "
			"the default value is 'on'.\n"
		"-c: describe what the snapshot is for, and so on.\n"
		"-F: the filesystem name.\n"
		"-h: for help information.\n"
		"-n: the snapshot's name.\n"
		"-r: the remote shell used for communication with remote "
			"target, the default value is 'ssh'.\n"
		"-t: the life cycle (seconds) for write barrier, "
			"the default value is %d seconds.\n",
		BARRIER_TIMEOUT_DEFAULT);
}

static int snapshot_create_check(struct snapshot_instance *si)
{
	char buf[PAGE_SIZE];
	FILE *fp;
	int rc = 0;

	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf) - 1,
		 "%s %s 'zfs list %s/%s@%s 2>/dev/null'",
		 si->si_rsh, si->si_mdt0->st_host, si->si_mdt0->st_pool,
		 si->si_mdt0->st_filesystem, si->si_ssname);
	fp = popen(buf, "r");
	if (fp == NULL) {
		SNAPSHOT_ADD_LOG(si, "Popen fail to create check: %s\n",
				 strerror(errno));
		return -errno;
	}

	if (snapshot_fgets(fp, buf, sizeof(buf)) != NULL) {
		fprintf(stderr, "The snapshot %s exists\n", si->si_ssname);
		rc = -EEXIST;
	}

	pclose(fp);
	return rc;
}

static int __snapshot_create(struct snapshot_instance *si,
			     struct list_head *head, const char *fsname,
			     const char *mgsnode, __u64 xtime)
{
	struct snapshot_target *st;
	pid_t pid;
	int rc;

	list_for_each_entry(st, head, st_list)
	{
		st->st_status = 0;
		st->st_ignored = 0;
		st->st_pid = 0;

		pid = fork();
		if (pid < 0) {
			SNAPSHOT_ADD_LOG(si, "Can't fork for create snapshot "
					 "(%s@%s <%s>) on the target "
					 "(%s:%x:%d): %s\n",
					 fsname, si->si_ssname,
					 si->si_comment, st->st_host,
					 st->st_role, st->st_index,
					 strerror(errno));
			return pid;
		}

		/* child */
		if (pid == 0) {
			char cmd[PAGE_SIZE];
			int len;

			memset(cmd, 0, sizeof(cmd));
			len = snprintf(cmd, sizeof(cmd) - 1,
				       "%s %s 'zfs snapshot "
				       "-o lustre:fsname=%s "
				       "-o lustre:magic=%s "
				       "-o lustre:ctime=%llu "
				       "-o lustre:mtime=%llu ",
				       si->si_rsh, st->st_host, fsname,
				       SNAPSHOT_MAGIC, xtime, xtime);
			if (len <= 0)
				exit(-EOVERFLOW);

			if (si->si_comment != NULL) {
				rc = snprintf(cmd + len, sizeof(cmd) - len - 1,
					      "-o lustre:comment=\"%s\" ",
					      si->si_comment);
				if (rc <= 0)
					exit(-EOVERFLOW);

				len += rc;
			}

			if (st->st_role & SR_OST) {
				rc = snprintf(cmd + len, sizeof(cmd) - len - 1,
					      "-o lustre:svname=%s-OST%04x "
					      "%s/%s@%s'",
					      fsname, st->st_index, st->st_pool,
					      st->st_filesystem, si->si_ssname);
			} else if (!(st->st_role & SR_MGS)) {
				rc = snprintf(cmd + len, sizeof(cmd) - len - 1,
					      "-o lustre:svname=%s-MDT%04x "
					      "%s/%s@%s'",
					      fsname, st->st_index, st->st_pool,
					      st->st_filesystem, si->si_ssname);
			} else if (si->si_mdt0 == si->si_mgs) {
				/* MGS is on MDT0 */
				LASSERT(st == si->si_mdt0);

				rc = snprintf(cmd + len, sizeof(cmd) - len - 1,
					      "-o lustre:svname=%s-MDT%04x "
					      "-o lustre:mgsnode=%s %s/%s@%s'",
					      fsname, st->st_index, mgsnode,
					      st->st_pool, st->st_filesystem,
					      si->si_ssname);
			} else {
				LASSERT(st == si->si_mgs);

				rc = snprintf(cmd + len, sizeof(cmd) - len - 1,
					      "%s/%s@%s'", st->st_pool,
					      st->st_filesystem, si->si_ssname);
			}

			if (rc <= 0)
				exit(-EOVERFLOW);

			rc = snapshot_exec(cmd);
			if (rc != 0)
				SNAPSHOT_ADD_LOG(si, "Can't execute \"%s\" on "
						 "target (%s:%x:%d): rc = %d\n",
						 cmd, st->st_host, st->st_role,
						 st->st_index, rc);

			exit(rc);
		} /* end of child */

		/* parent continue to run more snapshot commands in parallel. */
		st->st_pid = pid;
	}

	return 0;
}

static int __snapshot_destroy(struct snapshot_instance *si,
			      struct list_head *head);

static int snapshot_create(struct snapshot_instance *si)
{
	char *__argv[3];
	char buf[PAGE_SIZE];
	struct timeval tv;
	char new_fsname[9];
	int rc = 0;
	int rc1 = 0;
	int rc2 = 0;

	rc = snapshot_create_check(si);
	if (rc != 0)
		return rc;

	rc = gettimeofday(&tv, NULL);
	if (rc != 0)
		return rc;

	srandom(tv.tv_usec);
	sprintf(new_fsname, "%08x", (__u32)random());
	new_fsname[8] = '\0';

	rc = snapshot_get_mgsnode(si, buf, sizeof(buf));
	if (rc != 0)
		return rc;

	__argv[1] = si->si_fsname;
	/* 1. Get barrier */
	if (si->si_barrier) {
		char tbuf[8];

		memset(tbuf, 0, sizeof(tbuf));
		snprintf(tbuf, 7, "%u", si->si_timeout);
		__argv[0] = "barrier_freeze";
		__argv[2] = tbuf;
		rc = jt_barrier_freeze(3, __argv);
		if (rc != 0) {
			SNAPSHOT_ADD_LOG(si, "Can't set barrier within %u "
					 "seconds on %s: rc = %d\n",
					 si->si_timeout, si->si_fsname, rc);

			return rc;
		}
	}

	/* 2. Fork config llog on MGS */
	__argv[0] = "fork_lcfg";
	__argv[2] = new_fsname;
	rc = jt_lcfg_fork(3, __argv);
	if (rc != 0) {
		SNAPSHOT_ADD_LOG(si, "Can't fork config log for create "
				 "snapshot %s from %s to %s: rc = %d\n",
				 si->si_ssname, si->si_fsname, new_fsname, rc);
		goto out;
	}

	/* 3.1 Create snapshot on every MDT */
	rc = __snapshot_create(si, &si->si_mdts_list, new_fsname, buf,
			       tv.tv_sec);
	if (rc == 0)
		/* 3.2 Create snapshot on every OST */
		rc = __snapshot_create(si, &si->si_osts_list, new_fsname, buf,
				       tv.tv_sec);

	/* 4. Wait for all children, even though part of them maybe failed */
	snapshot_wait(si, &rc1);

out:
	/* 5. Put barrier */
	if (si->si_barrier) {
		if (rc == 0 && rc1 == 0) {
			struct barrier_ctl bc;

			__argv[0] = "barrier_stat";
			rc = __jt_barrier_stat(2, __argv, &bc);
			if (rc != 0) {
				SNAPSHOT_ADD_LOG(si, "Can't get barrier status "
						 "on %s: rc = %d\n",
						 si->si_fsname, rc);
			} else if (bc.bc_status != BS_FROZEN ||
				   bc.bc_timeout <= 0) {
				SNAPSHOT_ADD_LOG(si, "The barrier expired "
						 "on %s\n", si->si_fsname);
				rc = -ETIMEDOUT;
			}
		}

		__argv[0] = "barrier_thaw";
		rc2 = jt_barrier_thaw(2, __argv);
		if (rc2 != 0)
			SNAPSHOT_ADD_LOG(si, "Can't release barrier on %s: "
					 "rc = %d\n", si->si_fsname, rc2);
	}

	/* cleanup */
	if (rc != 0 || rc1 != 0) {
		si->si_force = true;
		__snapshot_destroy(si, &si->si_osts_list);
		__snapshot_destroy(si, &si->si_mdts_list);
		snapshot_wait(si, &rc2);

		__argv[0] = "erase_lcfg";
		__argv[1] = new_fsname;
		jt_lcfg_erase(2, __argv);
	}

	return rc != 0 ? rc : (rc1 != 0 ? rc1 : rc2);
}

int jt_snapshot_create(int argc, char **argv)
{
	struct snapshot_instance *si;
	struct option lopts_create[] = {
		{ "barrier",	optional_argument,	0,	'b' },
		{ "comment",	required_argument,	0,	'c' },
		{ "fsname",	required_argument,	0,	'F' },
		{ "help",	no_argument,		0,	'h' },
		{ "name",	required_argument,	0,	'n' },
		{ "rsh",	required_argument,	0,	'r' },
		{ "timeout",	required_argument,	0,	't' },
	};
	int rc = 0;

	si = snapshot_init(argc, argv, lopts_create, "b::c:F:hn:r:t:",
			   snapshot_create_usage, LOCK_EX, &rc);
	if (si == NULL)
		return rc;

	if (si->si_ssname == NULL) {
		fprintf(stderr,
			"Miss the snapshot name to be created\n");
		snapshot_create_usage();
		snapshot_fini(si);
		return -EINVAL;
	}

	rc = snapshot_create(si);
	if (rc != 0) {
		fprintf(stderr,
			"Can't create the snapshot %s\n", si->si_ssname);
		SNAPSHOT_ADD_LOG(si, "Can't create snapshot %s with "
				 "comment <%s> barrier <%s>, timeout "
				 "<%d>: %d\n",
				 si->si_ssname, si->si_comment,
				 si->si_barrier ? "enable" : "disable",
				 si->si_barrier ? si->si_timeout : -1, rc);
	} else {
		SNAPSHOT_ADD_LOG(si, "Create snapshot %s successfully "
				 "with comment <%s>, barrier <%s>, "
				 "timeout <%d>\n",
				 si->si_ssname, si->si_comment,
				 si->si_barrier ? "enable" : "disable",
				 si->si_barrier ? si->si_timeout : -1);
	}

	snapshot_fini(si);
	return rc;
}

static void snapshot_destroy_usage(void)
{
	fprintf(stderr,
		"Destroy the specified snapshot.\n"
		"Usage:\n"
		"snapshot_destroy [-f | --force] "
				 "<-F | --fsname fsname> [-h | --help] "
				 "<-n | --name ssname> "
				 "[-r | --rsh remote_shell]\n"
		"Options:\n"
		"-f: destroy the snapshot by force.\n"
		"-F: the filesystem name.\n"
		"-h: for help information.\n"
		"-n: the snapshot's name.\n"
		"-r: the remote shell used for communication with remote "
			"target, the default value is 'ssh'.\n");
}

static int __snapshot_destroy(struct snapshot_instance *si,
			      struct list_head *head)
{
	struct snapshot_target *st;
	pid_t pid;
	int rc;

	list_for_each_entry(st, head, st_list)
	{
		st->st_status = 0;
		st->st_ignored = 0;
		st->st_pid = 0;

		pid = fork();
		if (pid < 0) {
			SNAPSHOT_ADD_LOG(si, "Can't fork for destroy snapshot "
					 "%s on the target (%s:%x:%d): %s\n",
					 si->si_ssname, st->st_host,
					 st->st_role, st->st_index,
					 strerror(errno));
			return pid;
		}

		/* child */
		if (pid == 0) {
			char cmd[PAGE_SIZE];

			memset(cmd, 0, sizeof(cmd));
			if (si->si_force)
				snprintf(cmd, sizeof(cmd) - 1,
					 "%s %s 'umount -f %s/%s@%s "
					 "> /dev/null 2>&1; "
					 "zfs destroy -f %s/%s@%s'",
					 si->si_rsh, st->st_host, st->st_pool,
					 st->st_filesystem, si->si_ssname,
					 st->st_pool, st->st_filesystem,
					 si->si_ssname);
			else
				snprintf(cmd, sizeof(cmd) - 1,
					 "%s %s 'zfs destroy %s/%s@%s'",
					 si->si_rsh, st->st_host, st->st_pool,
					 st->st_filesystem, si->si_ssname);
			rc = snapshot_exec(cmd);
			if (rc != 0)
				SNAPSHOT_ADD_LOG(si, "Can't execute \"%s\" on "
						 "target (%s:%x:%d): rc = %d\n",
						 cmd, st->st_host, st->st_role,
						 st->st_index, rc);

			exit(rc);
		} /* end of child */

		/* parent continue to run more snapshot commands in parallel. */
		st->st_pid = pid;
	}

	return 0;
}

static int snapshot_destroy(struct snapshot_instance *si)
{
	char fsname[9];
	int rc = 0;
	int rc1 = 0;
	int rc2 = 0;
	int rc3 = 0;

	if (!si->si_force) {
		rc = snapshot_general_check(si);
		if (rc != 0)
			return rc;
	}

	rc = snapshot_get_fsname(si, fsname, sizeof(fsname));
	if (rc != 0)
		return rc;

	/* 1.1 Destroy snapshot on every OST */
	rc = __snapshot_destroy(si, &si->si_osts_list);
	if (!si->si_force) {
		if (rc != 0)
			return rc;

		__snapshot_wait(si, &si->si_osts_list, &rc);
		if (rc != 0)
			return rc;
	}

	/* 1.2 Destroy snapshot on every MDT */
	rc1 = __snapshot_destroy(si, &si->si_mdts_list);

	/* 2 Wait for all children, even though part of them maybe failed */
	snapshot_wait(si, &rc2);
	if (rc2 == -ENOENT && si->si_force)
		rc2 = 0;

	/* 3. Erase config llog from MGS */
	if ((rc == 0 && rc1 == 0 && rc2 == 0) || si->si_force) {
		char *__argv[2];

		__argv[0] = "erase_lcfg";
		__argv[1] = fsname;
		rc3 = jt_lcfg_erase(2, __argv);
		if (rc3 != 0 && errno == ENOENT)
			rc3 = 0;
		if (rc3 != 0)
			SNAPSHOT_ADD_LOG(si, "Can't erase config for destroy "
					 "snapshot %s, fsname %s: rc = %d\n",
					 si->si_ssname, fsname, rc3);
	}

	return rc != 0 ? rc : (rc1 != 0 ? rc1 : (rc2 != 0 ? rc2 : rc3));
}

int jt_snapshot_destroy(int argc, char **argv)
{
	struct snapshot_instance *si;
	struct option lopts_destroy[] = {
		{ "force",	no_argument,		0,	'f' },
		{ "fsname",	required_argument,	0,	'F' },
		{ "help",	no_argument,		0,	'h' },
		{ "name",	required_argument,	0,	'n' },
		{ "rsh",	required_argument,	0,	'r' },
	};
	int rc = 0;

	si = snapshot_init(argc, argv, lopts_destroy, "fF:hn:r:",
			   snapshot_destroy_usage, LOCK_EX, &rc);
	if (si == NULL)
		return rc;

	if (si->si_ssname == NULL) {
		fprintf(stderr,
			"Miss the snapshot name to be destroyed\n");
		snapshot_destroy_usage();
		snapshot_fini(si);
		return -EINVAL;
	}

	rc = snapshot_destroy(si);
	if (rc != 0) {
		fprintf(stderr,
			"Can't destroy the snapshot %s\n", si->si_ssname);
		SNAPSHOT_ADD_LOG(si, "Can't destroy snapshot %s with "
				 "force <%s>: %d\n", si->si_ssname,
				 si->si_force ? "enable" : "disable", rc);
	} else {
		SNAPSHOT_ADD_LOG(si, "Destroy snapshot %s successfully "
				 "with force <%s>\n", si->si_ssname,
				 si->si_force ? "enable" : "disable");
	}

	snapshot_fini(si);
	return rc;
}

static void snapshot_modify_usage(void)
{
	fprintf(stderr,
		"Change the specified snapshot's name and/or comment.\n"
		"Usage:\n"
		"snapshot_modify [-c | --comment comment] "
				"<-F | --fsname fsname> [-h | --help] "
				"<-n | --name ssname> [-N | --new new_ssname] "
				"[-r | --rsh remote_shell]\n"
		"Options:\n"
		"-c: update the snapshot's comment.\n"
		"-F: the filesystem name.\n"
		"-h: for help information.\n"
		"-n: the snapshot's name.\n"
		"-N: rename the snapshot's name as the new_ssname.\n"
		"-r: the remote shell used for communication with remote "
			"target, the default value is 'ssh'.\n");
}

static int snapshot_modify_check(struct snapshot_instance *si)
{
	int rc;

	if (si->si_new_ssname != NULL &&
	    strcmp(si->si_ssname, si->si_new_ssname) == 0) {
		fprintf(stderr, "The new snapshot's name is the same as "
			"the old one %s %s.\n",
			si->si_ssname, si->si_new_ssname);
		return -EPERM;
	}

	if (si->si_new_ssname == NULL && si->si_comment == NULL) {
		fprintf(stderr, "Miss options, nothing to be changed.\n");
		return -EINVAL;
	}

	rc = mdt0_is_lustre_snapshot(si);
	if (rc == 0 && si->si_new_ssname != NULL) {
		rc = target_is_mounted(si, si->si_mdt0, si->si_ssname);
		if (rc > 0) {
			fprintf(stderr,
				"snapshot %s is mounted, can't be renamed.\n",
				si->si_ssname);
			rc = -EBUSY;
		}
	}

	return rc;
}

static int __snapshot_modify(struct snapshot_instance *si,
			     struct list_head *head, __u64 xtime)
{
	struct snapshot_target *st;
	pid_t pid;
	int rc;

	list_for_each_entry(st, head, st_list)
	{
		st->st_status = 0;
		st->st_ignored = 0;
		st->st_pid = 0;

		pid = fork();
		if (pid < 0) {
			SNAPSHOT_ADD_LOG(si, "Can't fork for modify snapshot "
					 "(%s|%s, <%s>) on the target "
					 "(%s:%x:%d): %s\n",
					 si->si_ssname, si->si_new_ssname,
					 si->si_comment, st->st_host,
					 st->st_role, st->st_index,
					 strerror(errno));
			return pid;
		}

		/* child */
		if (pid == 0) {
			char cmd[PAGE_SIZE];

			memset(cmd, 0, sizeof(cmd));
			if (si->si_new_ssname != NULL && si->si_comment != NULL)
				snprintf(cmd, sizeof(cmd) - 1,
					 "%s %s 'zpool import -d %s %s > "
					 "/dev/null 2>&1; "
					 "zfs rename %s/%s@%s %s/%s@%s && "
					 "zfs set lustre:comment=\"%s\" "
					 "%s/%s@%s && "
					 "zfs set lustre:mtime=%llu %s/%s@%s'",
					 si->si_rsh, st->st_host, st->st_dir,
					 st->st_pool, st->st_pool,
					 st->st_filesystem, si->si_ssname,
					 st->st_pool, st->st_filesystem,
					 si->si_new_ssname, si->si_comment,
					 st->st_pool, st->st_filesystem,
					 si->si_new_ssname, xtime,
					 st->st_pool, st->st_filesystem,
					 si->si_new_ssname);
			else if (si->si_new_ssname != NULL)
				snprintf(cmd, sizeof(cmd) - 1,
					 "%s %s 'zpool import -d %s %s > "
					 "/dev/null 2>&1; "
					 "zfs rename %s/%s@%s %s/%s@%s && "
					 "zfs set lustre:mtime=%llu %s/%s@%s'",
					 si->si_rsh, st->st_host, st->st_dir,
					 st->st_pool, st->st_pool,
					 st->st_filesystem, si->si_ssname,
					 st->st_pool, st->st_filesystem,
					 si->si_new_ssname, xtime, st->st_pool,
					 st->st_filesystem, si->si_new_ssname);
			else if (si->si_comment != NULL)
				snprintf(cmd, sizeof(cmd) - 1,
					 "%s %s 'zpool import -d %s %s > "
					 "/dev/null 2>&1; zfs set "
					 "lustre:comment=\"%s\" %s/%s@%s && "
					 "zfs set lustre:mtime=%llu %s/%s@%s'",
					 si->si_rsh, st->st_host, st->st_dir,
					 st->st_pool, si->si_comment,
					 st->st_pool, st->st_filesystem,
					 si->si_ssname, xtime, st->st_pool,
					 st->st_filesystem, si->si_ssname);
			else
				exit(-EINVAL);

			rc = snapshot_exec(cmd);
			if (rc != 0)
				SNAPSHOT_ADD_LOG(si, "Can't execute \"%s\" on "
						 "target (%s:%x:%d): rc = %d\n",
						 cmd, st->st_host, st->st_role,
						 st->st_index, rc);

			exit(rc);
		} /* end of child */

		/* parent continue to run more snapshot commands in parallel. */
		st->st_pid = pid;
	}

	return 0;
}

static int snapshot_modify(struct snapshot_instance *si)
{
	time_t tt;
	int rc = 0;
	int rc1 = 0;

	rc = snapshot_modify_check(si);
	if (rc != 0)
		return rc;

	time(&tt);

	/* Modify snapshot on every MDT */
	rc = __snapshot_modify(si, &si->si_mdts_list, (__u64)tt);
	if (rc == 0)
		/* Modify snapshot on every OST */
		rc = __snapshot_modify(si, &si->si_osts_list, (__u64)tt);

	/* Wait for all children, even though part of them maybe failed */
	snapshot_wait(si, &rc1);

	return rc != 0 ? rc : rc1;
}

int jt_snapshot_modify(int argc, char **argv)
{
	struct snapshot_instance *si;
	struct option lopts_modify[] = {
		{ "comment",	required_argument,	0,	'c' },
		{ "fsname",	required_argument,	0,	'F' },
		{ "help",	no_argument,		0,	'h' },
		{ "name",	required_argument,	0,	'n' },
		{ "new",	required_argument,	0,	'N' },
		{ "rsh",	required_argument,	0,	'r' },
	};
	int rc = 0;

	si = snapshot_init(argc, argv, lopts_modify, "c:F:hn:N:r:",
			   snapshot_modify_usage, LOCK_EX, &rc);
	if (si == NULL)
		return rc;

	if (si->si_ssname == NULL) {
		fprintf(stderr,
			"Miss the snapshot name to be modified\n");
		snapshot_modify_usage();
		snapshot_fini(si);
		return -EINVAL;
	}

	rc = snapshot_modify(si);
	if (rc != 0) {
		fprintf(stderr,
			"Can't modify the snapshot %s\n", si->si_ssname);
		SNAPSHOT_ADD_LOG(si, "Can't modify snapshot %s with "
				 "name <%s>, comment <%s>: %d\n",
				 si->si_ssname, si->si_new_ssname,
				 si->si_comment, rc);
	} else {
		SNAPSHOT_ADD_LOG(si, "Modify snapshot %s successfully "
				 "with name <%s>, comment <%s>\n",
				 si->si_ssname, si->si_new_ssname,
				 si->si_comment);
	}

	snapshot_fini(si);
	return rc;
}

static void snapshot_list_usage(void)
{
	fprintf(stderr,
		"List the specified snapshot or all snapshots.\n"
		"Usage:\n"
		"snapshot_list [-d | --detail] "
			      "<-F | --fsname fsname> [-h | --help] "
			      "[-n | --name ssname] [-r | --rsh remote_shell]\n"
		"Options:\n"
		"-d: list every piece for the specified snapshot.\n"
		"-F: the filesystem name.\n"
		"-h: for help information.\n"
		"-n: the snapshot's name.\n"
		"-r: the remote shell used for communication with remote "
			"target, the default value is 'ssh'.\n");
}

static int snapshot_list_one(struct snapshot_instance *si,
			     struct snapshot_target *st)
{
	char buf[PAGE_SIZE];
	FILE *fp;
	int rc;

	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf) - 1,
		 "%s %s \"zpool import -d %s %s > /dev/null 2>&1; "
		 "zfs get all %s/%s@%s | grep lustre: | grep local$ | "
		 "awk '{ \\$1=\\\"\\\"; \\$NF=\\\"\\\"; print \\$0 }' | "
		 "sed -e 's/^ //'\"",
		 si->si_rsh, st->st_host, st->st_dir, st->st_pool,
		 st->st_pool, st->st_filesystem, si->si_ssname);
	fp = popen(buf, "r");
	if (fp == NULL) {
		SNAPSHOT_ADD_LOG(si, "Popen fail to list one: %s\n",
				 strerror(errno));
		return -errno;
	}

	if (si->si_detail) {
		char name[8];

		snapshot_role2name(name, st->st_role, st->st_index);
		printf("\nsnapshot_role: %s\n", name);
	}

	while (snapshot_fgets(fp, buf, PAGE_SIZE) != NULL) {
		__u64 xtime;
		char *ptr;

		if (strncmp(buf, "lustre:fsname",
			    strlen("lustre:fsname")) == 0) {
			ptr = strchr(buf, ' ');
			LASSERT(ptr != NULL);

			printf("snapshot_fsname: %s\n", ptr + 1);
			continue;
		}

		if (strncmp(buf, "lustre:comment",
			    strlen("lustre:comment")) == 0) {
			ptr = strchr(buf, ' ');
			LASSERT(ptr != NULL);

			printf("comment: %s\n", ptr + 1);
			continue;
		}

		if (strncmp(buf, "lustre:ctime",
			    strlen("lustre:ctime")) == 0) {
			ptr = strchr(buf, ' ');
			LASSERT(ptr != NULL);

			sscanf(ptr + 1, "%llu", &xtime);
			printf("create_time: %s", ctime((time_t *)&xtime));
			continue;
		}

		if (strncmp(buf, "lustre:mtime",
			    strlen("lustre:mtime")) == 0) {
			ptr = strchr(buf, ' ');
			LASSERT(ptr != NULL);

			sscanf(ptr + 1, "%llu", &xtime);
			printf("modify_time: %s", ctime((time_t *)&xtime));
			continue;
		}
	}

	pclose(fp);
	rc = target_is_mounted(si, st, si->si_ssname);
	if (rc < 0)
		printf("status: unknown\n");
	else if (rc == 0)
		printf("status: not mount\n");
	else
		printf("status: mounted\n");

	return rc;
}

static int __snapshot_list(struct snapshot_instance *si,
			   struct list_head *head)
{
	struct snapshot_target *st;
	int rc = 0;

	list_for_each_entry(st, head, st_list)
	{
		int rc1;

		rc1 = snapshot_list_one(si, st);
		if (rc1 < 0 || rc >= 0)
			rc = rc1;
	}

	return rc;
}

static int snapshot_list(struct snapshot_instance *si)
{
	int rc = 0;

	rc = snapshot_general_check(si);
	if (rc != 0)
		return rc;

	printf("\nfilesystem_name: %s\nsnapshot_name: %s\n",
	       si->si_fsname,si->si_ssname);

	if (!si->si_detail) {
		rc = snapshot_list_one(si, si->si_mdt0);
	} else {
		int rc1;

		rc = __snapshot_list(si, &si->si_mdts_list);
		rc1 = __snapshot_list(si, &si->si_osts_list);
		if (rc >= 0)
			rc = rc1;
	}

	return rc < 0 ? rc : 0;
}

static int snapshot_list_all(struct snapshot_instance *si)
{
	struct list_sub_item {
		struct list_head lsi_list;
		char lsi_ssname[0];
	};

	struct list_head list_sub_items;
	struct list_sub_item *lsi;
	char buf[PAGE_SIZE];
	FILE *fp;
	int rc = 0;

	INIT_LIST_HEAD(&list_sub_items);
	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf) - 1,
		 "%s %s \"zfs get -H -r lustre:magic %s/%s | "
		 "grep %s | awk '{ print \\$1 }' | cut -d@ -f2\"",
		 si->si_rsh, si->si_mdt0->st_host, si->si_mdt0->st_pool,
		 si->si_mdt0->st_filesystem, SNAPSHOT_MAGIC);
	fp = popen(buf, "r");
	if (fp == NULL) {
		SNAPSHOT_ADD_LOG(si, "Popen fail to list ssnames: %s\n",
				 strerror(errno));
		return -errno;
	}

	while (snapshot_fgets(fp, buf, PAGE_SIZE) != NULL) {
		lsi = malloc(strlen(buf) + 1 +
			sizeof(struct list_sub_item));
		if (lsi == NULL) {
			SNAPSHOT_ADD_LOG(si, "NOT enough memory\n");
			rc = -ENOMEM;
			break;
		}

		strcpy(lsi->lsi_ssname, buf);
		list_add(&lsi->lsi_list, &list_sub_items);
	}

	pclose(fp);
	while (!list_empty(&list_sub_items)) {
		lsi = list_entry(list_sub_items.next,
				 struct list_sub_item, lsi_list);
		list_del(&lsi->lsi_list);
		if (rc == 0) {
			si->si_ssname = lsi->lsi_ssname;
			rc = snapshot_list(si);
			si->si_ssname = NULL;
		}

		free(lsi);
	}

	return rc;
}

int jt_snapshot_list(int argc, char **argv)
{
	struct snapshot_instance *si;
	struct option lopts_list[] = {
		{ "detail",	no_argument,		0,	'd' },
		{ "fsname",	required_argument,	0,	'F' },
		{ "help",	no_argument,		0,	'h' },
		{ "name",	required_argument,	0,	'n' },
		{ "rsh",	required_argument,	0,	'r' },
	};
	int rc = 0;

	si = snapshot_init(argc, argv, lopts_list, "dF:hn:r:",
			   snapshot_list_usage, LOCK_SH, &rc);
	if (si == NULL)
		return rc;

	if (si->si_ssname != NULL)
		rc = snapshot_list(si);
	else
		rc = snapshot_list_all(si);

	if (rc != 0) {
		fprintf(stderr,
			"Can't list the snapshot %s\n", si->si_ssname);
		SNAPSHOT_ADD_LOG(si, "Can't list snapshot %s with detail "
				 "<%s>: %d\n", si->si_ssname,
				 si->si_detail ? "yes" : "no", rc);
	}

	snapshot_fini(si);
	return rc;
}

static void snapshot_mount_usage(void)
{
	fprintf(stderr,
		"Mount the specified snapshot.\n"
		"Usage:\n"
		"snapshot_mount <-F | --fsname fsname> [-h | --help] "
			       "<-n | --name ssname> "
			       "[-r | --rsh remote_shell]\n"
		"Options:\n"
		"-F: the filesystem name.\n"
		"-h: for help information.\n"
		"-n: the snapshot's name.\n"
		"-r: the remote shell used for communication with remote "
			"target, the default value is 'ssh'.\n");
}

static int snapshot_mount_check(struct snapshot_instance *si, char *fsname,
				int fslen, bool *mgs_running)
{
	int rc;

	rc = mdt0_is_lustre_snapshot(si);
	if (rc != 0)
		return rc;

	rc = snapshot_get_fsname(si, fsname, fslen);
	if (rc < 0)
		return rc;

	rc = target_is_mounted(si, si->si_mgs, NULL);
	if (rc > 0) {
		*mgs_running = true;
		rc = 0;
	}

	return rc;
}

static int snapshot_mount_target(struct snapshot_instance *si,
				 struct snapshot_target *st, const char *optstr)
{
	char cmd[PAGE_SIZE];
	char name[8];
	int rc;

	rc = target_is_mounted(si, st, si->si_ssname);
	if (rc < 0)
		return rc;

	if (rc > 0)
		return -ESRCH;

	memset(cmd, 0, sizeof(cmd));
	memset(name, 0, sizeof(name));
	snapshot_role2name(name, st->st_role, st->st_index);
	snprintf(cmd, sizeof(cmd) - 1,
		 "%s %s 'zpool import -d %s %s > /dev/null 2>&1; "
		 "mkdir -p /mnt/%s_%s && mount -t lustre "
		 "-o rdonly_dev%s %s/%s@%s /mnt/%s_%s'",
		 si->si_rsh, st->st_host, st->st_dir, st->st_pool,
		 si->si_ssname, name, st != si->si_mdt0 ? "" : optstr,
		 st->st_pool, st->st_filesystem, si->si_ssname,
		 si->si_ssname, name);
	rc = snapshot_exec(cmd);
	if (rc != 0)
		SNAPSHOT_ADD_LOG(si, "Can't execute \"%s\" on the target "
				 "(%s:%x:%d): rc = %d\n", cmd, st->st_host,
				 st->st_role, st->st_index, rc);

	return rc;
}

static int __snapshot_mount(struct snapshot_instance *si,
			    struct list_head *head)
{
	struct snapshot_target *st;
	pid_t pid;
	int rc;

	list_for_each_entry(st, head, st_list)
	{
		if (st == si->si_mgs || st == si->si_mdt0)
			continue;

		st->st_status = 0;
		st->st_ignored = 0;
		st->st_pid = 0;

		pid = fork();
		if (pid < 0) {
			SNAPSHOT_ADD_LOG(si, "Can't fork for mount snapshot "
					 "%s on target (%s:%x:%d): %s\n",
					 si->si_ssname, st->st_host,
					 st->st_role, st->st_index,
					 strerror(errno));
			return pid;
		}

		/* child */
		if (pid == 0) {
			rc = snapshot_mount_target(si, st, "");
			exit(rc);
		}

		/* parent continue to run more snapshot commands in parallel. */
		st->st_pid = pid;
	}

	return 0;
}

static int __snapshot_umount(struct snapshot_instance *si,
			     struct list_head *head);

static int snapshot_mount(struct snapshot_instance *si)
{
	struct snapshot_target *st;
	int needed = 0;
	int failed = 0;
	int rc = 0;
	int rc1 = 0;
	char fsname[9];
	bool mdt0_mounted = false;
	bool mgs_running = false;

	rc = snapshot_mount_check(si, fsname, sizeof(fsname), &mgs_running);
	if (rc < 0) {
		fprintf(stderr,
			"Can't mount the snapshot %s: %s\n",
			si->si_ssname, strerror(-rc));
		return rc;
	}

	/* 1. MGS is not mounted yet, mount the MGS firstly */
	si->si_mgs->st_ignored = 0;
	si->si_mgs->st_pid = 0;
	if (!mgs_running) {
		rc = snapshot_mount_target(si, si->si_mgs, "");
		if (unlikely(rc == -ESRCH)) {
			si->si_mgs->st_ignored = 1;
			rc = 0;
		}

		if (rc < 0) {
			fprintf(stderr,
				"Can't mount the snapshot %s: %s\n",
				si->si_ssname, strerror(-rc));
			return rc;
		}

		if (si->si_mgs == si->si_mdt0)
			mdt0_mounted = true;
	}

	/* 2. Mount MDT0 if it is not combined with the MGS. */
	if (!mdt0_mounted) {
		si->si_mdt0->st_ignored = 0;
		si->si_mdt0->st_pid = 0;
		rc = snapshot_mount_target(si, si->si_mdt0, ",nomgs");
		if (rc != 0)
			goto cleanup;
	}

	/* 3.1 Mount other MDTs in parallel */
	rc = __snapshot_mount(si, &si->si_mdts_list);
	if (rc == 0)
		/* 3.2 Mount OSTs in parallel */
		rc = __snapshot_mount(si, &si->si_osts_list);

	/* Wait for all children, even though part of them maybe failed */
	failed = snapshot_wait(si, &rc1);

	list_for_each_entry(st, &si->si_mdts_list, st_list) {
		if (!st->st_ignored)
			needed++;
	}

	list_for_each_entry(st, &si->si_osts_list, st_list) {
		if (!st->st_ignored)
			needed++;
	}

cleanup:
	if (rc != 0 || rc1 != 0) {
		int rc2 = 0;

		__snapshot_umount(si, &si->si_mdts_list);
		__snapshot_umount(si, &si->si_osts_list);
		snapshot_wait(si, &rc2);

		if (rc != 0) {
			fprintf(stderr,
				"Can't mount the snapshot %s: %s\n",
				si->si_ssname, strerror(-rc));
		} else {
			LASSERT(failed != 0);

			fprintf(stderr,
				"%d of %d pieces of the snapshot %s "
				"can't be mounted: %s\n",
				failed, needed, si->si_ssname, strerror(-rc1));

		}

		return rc != 0 ? rc : rc1;
	}

	if (needed == 0) {
		fprintf(stderr,
			"The snapshot %s has already been mounted by other\n",
			si->si_ssname);
		return -EALREADY;
	}

	fprintf(stdout, "mounted the snapshot %s with fsname %s\n",
		si->si_ssname, fsname);

	return 0;
}

int jt_snapshot_mount(int argc, char **argv)
{
	struct snapshot_instance *si;
	struct option lopts_mount[] = {
		{ "fsname",	required_argument,	0,	'F' },
		{ "help",	no_argument,		0,	'h' },
		{ "name",	required_argument,	0,	'n' },
		{ "rsh",	required_argument,	0,	'r' },
	};
	int rc = 0;

	si = snapshot_init(argc, argv, lopts_mount, "F:hn:r:",
			   snapshot_mount_usage, LOCK_EX, &rc);
	if (si == NULL)
		return rc;

	if (si->si_ssname == NULL) {
		fprintf(stderr,
			"Miss the snapshot name to be mounted\n");
		snapshot_mount_usage();
		snapshot_fini(si);
		return -EINVAL;
	}

	rc = snapshot_mount(si);
	if (rc != 0)
		SNAPSHOT_ADD_LOG(si, "Can't mount snapshot %s: %d\n",
				 si->si_ssname, rc);
	else
		SNAPSHOT_ADD_LOG(si, "The snapshot %s is mounted\n",
				 si->si_ssname);

	snapshot_fini(si);
	return rc;

}

static void snapshot_umount_usage(void)
{
	fprintf(stderr,
		"Umount the specified snapshot.\n"
		"Usage:\n"
		"snapshot_umount [-F | --fsname fsname] [-h | --help] "
				"<-n | --name ssname> "
				"[-r | --rsh remote_shell]\n"
		"Options:\n"
		"-F: the filesystem name.\n"
		"-h: for help information.\n"
		"-n: the snapshot's name.\n"
		"-r: the remote shell used for communication with remote "
			"target, the default value is 'ssh'.\n");
}

static int __snapshot_umount(struct snapshot_instance *si,
			     struct list_head *head)
{
	struct snapshot_target *st;
	pid_t pid;
	int rc;

	list_for_each_entry(st, head, st_list)
	{
		st->st_status = 0;
		st->st_ignored = 0;
		st->st_pid = 0;

		pid = fork();
		if (pid < 0) {
			SNAPSHOT_ADD_LOG(si, "Can't fork for umount snapshot "
					 "%s on target (%s:%x:%d): %s\n",
					 si->si_ssname, st->st_host,
					 st->st_role, st->st_index,
					 strerror(errno));
			return pid;
		}

		/* child */
		if (pid == 0) {
			char cmd[PAGE_SIZE];

			rc = target_is_mounted(si, st, si->si_ssname);
			if (rc < 0)
				exit(rc);

			if (rc == 0)
				exit(-ESRCH);

			memset(cmd, 0, sizeof(cmd));
			snprintf(cmd, sizeof(cmd) - 1,
				 "%s %s 'umount %s/%s@%s'",
				 si->si_rsh, st->st_host, st->st_pool,
				 st->st_filesystem, si->si_ssname);
			rc = snapshot_exec(cmd);

			exit(rc);
		}

		/* parent continue to run more snapshot commands in parallel. */
		st->st_pid = pid;
	}

	return 0;
}

static int snapshot_umount(struct snapshot_instance *si)
{
	struct snapshot_target *st;
	int needed = 0;
	int failed;
	int rc = 0;
	int rc1 = 0;
	int rc2 = 0;

	rc = snapshot_general_check(si);
	if (rc < 0) {
		fprintf(stderr,
			"Can't umount the snapshot %s: %s\n",
			si->si_ssname, strerror(-rc));
		return rc;
	}

	rc = __snapshot_umount(si, &si->si_mdts_list);
	rc1 = __snapshot_umount(si, &si->si_osts_list);
	failed = snapshot_wait(si, &rc2);

	list_for_each_entry(st, &si->si_mdts_list, st_list) {
		if (!st->st_ignored)
			needed++;
	}

	list_for_each_entry(st, &si->si_osts_list, st_list) {
		if (!st->st_ignored)
			needed++;
	}

	if (needed == 0) {
		fprintf(stderr,
			"The snapshot %s has not been mounted\n",
			si->si_ssname);
		return -EALREADY;
	}

	if (failed != 0) {
		LASSERT(rc2 != 0);

		fprintf(stderr,
			"%d of %d pieces of the snapshot %s "
			"can't be umounted: %s\n",
			failed, needed, si->si_ssname, strerror(-rc2));
	}

	return rc != 0 ? rc : (rc1 != 0 ? rc1 : rc2);
}

int jt_snapshot_umount(int argc, char **argv)
{
	struct snapshot_instance *si;
	struct option lopts_umount[] = {
		{ "fsname",	required_argument,	0,	'F' },
		{ "help",	no_argument,		0,	'h' },
		{ "name",	required_argument,	0,	'n' },
		{ "rsh",	required_argument,	0,	'r' },
	};
	int rc = 0;

	si = snapshot_init(argc, argv, lopts_umount, "F:hn:r:",
			   snapshot_umount_usage, LOCK_EX, &rc);
	if (si == NULL)
		return rc;

	if (si->si_ssname == NULL) {
		fprintf(stderr,
			"Miss the snapshot name to be umounted\n");
		snapshot_umount_usage();
		snapshot_fini(si);
		return -EINVAL;
	}

	rc = snapshot_umount(si);
	if (rc < 0)
		SNAPSHOT_ADD_LOG(si, "Can't umount snapshot %s: %d\n",
				 si->si_ssname, rc);
	else
		SNAPSHOT_ADD_LOG(si, "the snapshot %s have been umounted\n",
				 si->si_ssname);

	snapshot_fini(si);
	return rc;
}