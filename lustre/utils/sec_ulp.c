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

#include "sec_ulp.h"

/** #include <sepol/policydb/policydb.h> */
#include <sepol/policydb/services.h>

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

static void test_handler(int signo)
{
	printf("caught signal!\n");
	//exit(EXIT_SUCCESS);
}



int main(int argc, char **argv) {
	int				fd;
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
	sepol_security_class_t		tclass = 6;
	sidtab_t			sidtab;

	/** TODO: Check for pidfile */

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
	if (signal(SIGUSR1, test_handler) == SIG_ERR) {
		perror("signal()");
		exit(EXIT_FAILURE);
	}
	sepol_set_policydb(&policydb);
	sepol_set_sidtab(&sidtab);

	if (policydb_load_isids(&policydb, &sidtab))
		exit(1);

	printf("%s:  policy configuration loaded\n", argv[0]);

	/** Establish a netlink connection */

	/** Daemonize */
	if (daemon(0, 1) == -1)
		perror("daemon()");

	if (sepol_context_to_sid("root:sysadm_r:sysadm_t:s0-s15:c0.c1023",
				 sizeof("root:sysadm_t:sysadm_t:s0-s15:c0.c1023"),
				 &ssid) < 0) {
		printf("sepol_context_to_sid() failed!\n");
		exit(EXIT_FAILURE);
	}
	else
		printf("sid is %u\n", ssid);

	if (sepol_context_to_sid("user_u:object_r:file_t:s5:c1",
				 sizeof("user_u:object_r:file_t:s5:c1"),
				 &tsid) < 0) {
		printf("sepol_context_to_sid() failed!\n");
		exit(EXIT_FAILURE);
	}
	else
		printf("sid is %u\n", tsid);

	rc = sepol_compute_av(ssid, tsid, tclass, 0, &avd);
	switch (rc) {
		case 0:
			printf("sepol_compute_av() results: "
			       "allowed: %x decided: %x auditallow: %x"
			       "auditdeny: %x seqno: %u\n",
			       avd.allowed, avd.decided, avd.auditallow,
			       avd.auditdeny, avd.seqno);

			break;

		case -EINVAL:
			printf("sepol_compute_av(): invalid sid!\n");

			break;

		default:
			printf("return code 0x%x\n", rc);

			break;
	}

	return 0;
}
