#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <linux/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <syslog.h>

#include "sec_ulp.h"

/** #include <sepol/policydb/policydb.h> */
#include <sepol/policydb/services.h>

#define NETLINK_SEC_UPM		31
#define MAX_PAYLOAD		128
#define LSELD_PIDFILE		"/var/run/lseld.pid"

#if 0
int display_bools(void)
{
	uint32_t i;

	for (i = 0; i < policydbp->p_bools.nprim; i++) {
		printf("%s : %d\n", policydbp->p_bool_val_to_name[i],
		       policydbp->bool_val_to_struct[i]->state);
	}
	return 0;
}
#endif

int			sock_fd;
struct sockaddr_nl	src_addr;
struct sockaddr_nl	dest_addr;
struct nlmsghdr	       *nlh;
struct iovec		iov;
struct msghdr		msg;
char			scon[128];
char			tcon[128];
sepol_security_class_t	tclass;
char			buf[100];
int			fd;




static void sig_handler(int signo)
{
	switch (signo) {
	case SIGTERM:
		if (sock_fd)
			close(sock_fd);
		if (fd)
			close(fd);
		closelog();

		if (unlink(LSELD_PIDFILE) == -1)
			syslog(LOG_ERR, "unlink() failed with  %s \n",
			       strerror(errno));
		exit(EXIT_SUCCESS);

		break;

	default:
		syslog(LOG_ERR, "Signal %s should never be caught!\n",
		       strsignal(signo));
		break;
	}
}




int main(int argc, char **argv) {
	int				pidfd;
	int				rc;
	void			       *map;
	/** Use a hard-coded policy file for now */
	const char		       *file = "/etc/selinux/mls/policy/policy.24";
	struct stat			sb;
	struct policy_file		pf;
	policydb_t			policydb;
	struct sepol_av_decision	avd;
	sepol_security_id_t		ssid;
	sepol_security_id_t		tsid;
	sidtab_t			sidtab;

	pidfd = open(LSELD_PIDFILE, O_RDWR | O_CREAT | O_EXCL,
		     S_IRUSR | S_IWUSR);
	if (pidfd < 0) {
		fprintf(stderr, "Can't open '%s':  %s\n",
			file, strerror(errno));
		exit(1);
	}

	openlog(NULL, LOG_CONS | LOG_PID, LOG_USER);

	/**
	 * Only handle binary policies for now
	 * if (binary) {
	 */
	fd = open(file, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Can't open '%s':  %s\n",
			file, strerror(errno));
		exit(1);
	}
	if (fstat(fd, &sb) < 0) {
		fprintf(stderr, "Can't stat '%s':  %s\n",
			file, strerror(errno));
		exit(1);
	}
	map = mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd,
		   0);
	if (map == MAP_FAILED) {
		fprintf(stderr, "Can't map '%s':  %s\n",
			file, strerror(errno));
		exit(1);
	}
	policy_file_init(&pf);
	pf.type = PF_USE_MEMORY;
	pf.data = map;
	pf.len = sb.st_size;
	if (policydb_init(&policydb)) {
		fprintf(stderr, "%s:  policydb_init:  Out of memory!\n",
			argv[0]);
		exit(1);
	}
	rc = policydb_read(&policydb, &pf, 1);
	if (rc) {
		fprintf(stderr,
			"%s:  error(s) encountered while parsing configuration\n",
			argv[0]);
		exit(1);
	}

	printf("%s:  policy configuration loaded\n", argv[0]);

	sepol_set_policydb(&policydb);
	sepol_set_sidtab(&sidtab);

	if (policydb_load_isids(&policydb, &sidtab))
		exit(1);
		//exit(EXIT_FAILURE);

	printf("%s:  policy configuration loaded\n", argv[0]);
	syslog(LOG_INFO, "%s:  policy configuration loaded\n", argv[0]);

	/** Establish a netlink connection */
	sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_SEC_UPM);
	if (sock_fd < 0) {
		fprintf(stderr, "Can't create socket\n");
		syslog(LOG_INFO, "Can't create socket\n");
		exit(EXIT_FAILURE);
	}

	/** Daemonize; the parent process should return to
	 * obd_security_upm_init() at this point.
	 */
	if (daemon(0, 1) == -1) {
		syslog(LOG_ERR, "daemon() failed with  %s \n",
		       strerror(errno));
		exit(EXIT_FAILURE);
	}

	/** Write the pidfile right after daemonizing, so that
	 * obd_security_upm_init() reads the data in time.
	 */
	snprintf(buf, sizeof(buf), "%ld\n", (long) getpid());
	/** TODO: Add error checking */
	write(pidfd, buf, strlen(buf));
	close(pidfd);

	/** TODO: Make this a high-priority task, and lock it in memory or
	 * otherwise avoid swapping it out, as we need to avoid long delays
	 * in response time. sched_setaffinity() or others? Make multithreaded?
	 * Check kernel cache size, as it might fit all of the policy, so it
	 * could be read in all during startup?
	 */
	if (signal(SIGTERM, sig_handler) == SIG_ERR) {
		syslog(LOG_ERR, "signal() failed with  %s \n",
		       strerror(errno));
		exit(EXIT_FAILURE);
	}
	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid(); /* self pid */

	if (bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr)) == -1) {
		syslog(LOG_ERR, "bind() failed with  %s \n",
		       strerror(errno));
		exit(EXIT_FAILURE);
	}

	printf("Waiting for message from kernel\n");
	syslog(LOG_INFO, "Waiting for message from kernel\n");

	while (1) {
		__u32 seq;

		nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
		memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
		nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
		nlh->nlmsg_pid = getpid();
		nlh->nlmsg_flags = 0;
#if 0
		nlh->nlmsg_type
		nlh->nlmsg_seq
#endif

		memset(&dest_addr, 0, sizeof(dest_addr));
		dest_addr.nl_family = AF_NETLINK;
		dest_addr.nl_pid = 0; /* For Linux Kernel */
		dest_addr.nl_groups = 0; /* unicast */

		iov.iov_base = (void *)nlh;
		iov.iov_len = nlh->nlmsg_len;
		msg.msg_name = (void *)&dest_addr;
		msg.msg_namelen = sizeof(dest_addr);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;

		/* Read message from kernel */
		recvmsg(sock_fd, &msg, 0);
		syslog(LOG_INFO, "Received message payload: %s, seq = %d\n",
		       (char *)NLMSG_DATA(nlh), nlh->nlmsg_seq);

		seq = nlh->nlmsg_seq;

		sscanf((char *)NLMSG_DATA(nlh), "%s %s %hu", scon, tcon,
		       (__u16*)&tclass);

		syslog(LOG_INFO, "Converted message to scon = %s tcon = %s "
		       "class = %hu\n", &scon[0], &tcon[0], tclass);

		if (sepol_context_to_sid(&scon[0],
					 sizeof(scon),
					 &ssid) < 0) {
			syslog(LOG_INFO, "sepol_context_to_sid() failed!\n");
			exit(EXIT_FAILURE);
		}
		else
			syslog(LOG_INFO, "ssid is %u\n", ssid);

		if (sepol_context_to_sid(&tcon[0],
					 sizeof(tcon),
					 &tsid) < 0) {
			syslog(LOG_INFO, "sepol_context_to_sid() failed!\n");
			exit(EXIT_FAILURE);
		}
		else
			syslog(LOG_INFO, "tsid is %u\n", tsid);
		syslog(LOG_INFO, "Sending message to kernel\n");

		rc = sepol_compute_av(ssid, tsid, tclass, 0, &avd);
		switch (rc) {
			case 0:
				syslog(LOG_INFO, "sepol_compute_av() results: "
				       "allowed: %x decided: %x auditallow: %x "
				       "auditdeny: %x seqno: %u\n",
				       avd.allowed, avd.decided, avd.auditallow,
				       avd.auditdeny, avd.seqno);

				break;

			case -EINVAL:
				syslog(LOG_INFO, "sepol_compute_av(): invalid sid!\n");

				break;

			default:
				syslog(LOG_INFO, "return code 0x%x\n", rc);

				break;
		}
		/** Send AVC reply to the SEC */
		memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
		snprintf((char *)NLMSG_DATA(nlh), MAX_PAYLOAD,
			 "%x ffffffff %x %x %u 0", avd.allowed,
			 avd.auditallow, avd.auditdeny, avd.seqno);

		nlh->nlmsg_seq = seq;

		syslog(LOG_INFO, "Sending AVD reply to SEC: %s, seq = %d\n",
		       (char *)NLMSG_DATA(nlh), nlh->nlmsg_seq);

#if 0
		sendmsg(sock_fd, &msg, 0);
		memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
		nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
		nlh->nlmsg_pid = getpid();
		nlh->nlmsg_flags = 0;
		strcpy(NLMSG_DATA(nlh), "LSELD is running");

#endif
		sendmsg(sock_fd, &msg, 0);

		free(nlh);

	}
	//raise(SIGTERM);

	return 0;
}
