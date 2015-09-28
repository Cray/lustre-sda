#!/bin/bash
#
# Test basic functionality of SELinux support.
#

# Without this option, debugfs may fail to show "sanity.selinux" from an external block/inode
OST_FS_MKFS_OPTS=${OST_FS_MKFS_OPTS:-"-I 512"}

set -e

FAIL_ON_ERROR=false

ONLY=${ONLY:-"$*"}

LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging

# bug number:
ALWAYS_EXCEPT="$SANITY_SELINUX_EXCEPT"

[ "$SLOW" = "no" ] && EXCEPT_SLOW=""

build_test_filter
check_and_setup_lustre
mkdir -p $MOUNT2
mount_client $MOUNT2

assert_DIR
rm -rf $DIR/[df][0-9]*

sestatus | egrep "Current mode:[[:space:]]*permissive" || error "client non-permissive"
sestatus | egrep "Policy from config file:[[:space:]]*mls" || error "client non-mls"

do_facet mds1 'sestatus | egrep "Current mode:[[:space:]]*permissive"' || error "mds non-permissive"
do_facet mds1 'sestatus | egrep "Policy from config file:[[:space:]]*mls"' || error "mds non-mls"

ost_obj_stat() {
	local have_obdidx=false
	$GETSTRIPE $1 | while read obdidx oid hex seq; do
		# skip lines up to and including "obdidx"
		[ -z "$obdidx" ] && break
		[ "$obdidx" = "obdidx" ] && have_obdidx=true && continue
		$have_obdidx || continue

		local ost=$((obdidx + 1))
		local dev=$(ostdevname $ost)

		local obj_file="O/$seq/d$((oid %32))/$oid"
		do_facet ost$ost "sync; $DEBUGFS -c -R 'stat $obj_file' $dev 2>/dev/null"
	done
}

test_1() {
	echo "=== step 1 ==="
	touch $DIR/$tfile-f1
	lfs setstripe -c 2 $DIR/$tfile-f2
	mkdir $DIR/$tfile-d1
	mkfifo $DIR/$tfile-p1
	mknod $DIR/$tfile-b1 b 1 1
	mknod $DIR/$tfile-c1 c 1 1
	ln -s $DIR/$tfile-f1 $DIR/$tfile-l1
	nc -lU $DIR/$tfile-s1 & sleep 1
	kill %1
	ls -salhZ $DIR

	echo "=== step 2 ==="
	echo 3 > /proc/sys/vm/drop_caches
	ls -salZ $DIR

	echo "=== step 3 ==="
	local dev=$(mdsdevname 1)
	do_facet mds1 "sync; $DEBUGFS -c -R 'stat ROOT/$tfile-f1' $dev 2>/dev/null" | grep "selinux ="
	do_facet mds1 "sync; $DEBUGFS -c -R 'stat ROOT/$tfile-f2' $dev 2>/dev/null" | grep "selinux ="
	do_facet mds1 "sync; $DEBUGFS -c -R 'stat ROOT/$tfile-d1' $dev 2>/dev/null" | grep "selinux ="
	do_facet mds1 "sync; $DEBUGFS -c -R 'stat ROOT/$tfile-p1' $dev 2>/dev/null" | grep "selinux ="
	do_facet mds1 "sync; $DEBUGFS -c -R 'stat ROOT/$tfile-l1' $dev 2>/dev/null" | grep "selinux ="
	do_facet mds1 "sync; $DEBUGFS -c -R 'stat ROOT/$tfile-b1' $dev 2>/dev/null" | grep "selinux ="
	do_facet mds1 "sync; $DEBUGFS -c -R 'stat ROOT/$tfile-c1' $dev 2>/dev/null" | grep "selinux ="
	do_facet mds1 "sync; $DEBUGFS -c -R 'stat ROOT/$tfile-s1' $dev 2>/dev/null" | grep "selinux ="

	echo "=== step 4 ==="
	dd if=/dev/zero of=$DIR/$tfile-f1 bs=1M count=10 oflag=direct
	ost_obj_stat $DIR/$tfile-f1 | grep "selinux ="
	dd if=/dev/zero of=$DIR/$tfile-f2 bs=1M count=10 oflag=direct
	ost_obj_stat $DIR/$tfile-f2 | grep "selinux ="
	chcon "root:object_r:file_t:s1" $DIR/$tfile-f2
	sync; sleep 10; sync
	ost_obj_stat $DIR/$tfile-f2 | grep "selinux ="

	echo "=== step 5 ==="

	touch $DIR/$tfile-f3
	chcon "root:object_r:file_t:s1" $DIR/$tfile-f3
	(
		chcon "root:object_r:file_t:s2" $DIR2/$tfile-f3
		log "should show root:object_r:file_t:s2"
		ls -salZ $DIR/$tfile-f3
	) 2>$DIR/$tfile-f3
	echo "should show root:object_r:file_t:s2"
	ls -salZ $DIR/$tfile-f3

}
run_test 1 "basic tests"

test_2() {
	SYSADM="runcon sysadm_u:sysadm_r:sysadm_t:s0-s15:c0.c1023" 
	ALICE="runcon staff_u:staff_r:staff_t:s2:c0.c1023"
	BOB="runcon staff_u:staff_r:staff_t:s1:c0.c255"
	SECADM="runcon root:secadm_r:secadm_t:s0-s15:c0.c1023"
	echo "sysadm:"; $SYSADM id -Z
	echo "alice:"; $ALICE id -Z
	echo "bob:"; $BOB id -Z
	echo "secadm:"; $SECADM id -Z

	chmod 777 $DIR
	umask 000
	
	TESTDIR=$DIR/$tdir
	TESTDIR2=$MOUNT2/$tdir
	$SYSADM rm -fR $TESTDIR
	$SYSADM mkdir $TESTDIR
	$SYSADM chcon user_u:object_r:user_home_dir_t:s1:c0.c255-s2:c0.c1023 $TESTDIR
	echo "sysadm ls directory1"
	$SYSADM ls -salZ $TESTDIR
	echo "sysadm ls directory2"
	$SYSADM ls -salZ $TESTDIR2

	echo "alice ls directory"
	$ALICE ls -lZ $TESTDIR
	echo "bob ls directory"
	$BOB ls -lZ $TESTDIR2

	echo "Files with s1"
	# bob (s1:c0.c255) creates foofile.txt (s1:c0.c255)
	$BOB dd of=$TESTDIR2/foofile.txt <<< "some text" || error "can't create file"
	# list directory
	$SECADM ls -salZ $TESTDIR
	# bob (s1:c0:c255) can write to foofile.txt (s1:c0.c255)
	$BOB cat $TESTDIR2/foofile.txt | grep "some text" || error "bob can't read file"

	# alice (s2:c0.c1023) can read foofile.t (s1:c0.c255)
	$ALICE cat $TESTDIR/foofile.txt | grep "some text" || error "alice can't read file"
	# alice (s2:c0.c1023)  CAN NOT write to foofile.txt (s1:c0.c255) 
	# s2 != s1
	sleep 1
	$ALICE dd of=$TESTDIR/foofile.txt <<< "another text" && error "alice not blocked"
	ausearch -ts now  -m avc -sv no | grep comm=mdt

	echo "Files with c0.c1023"
	# sec_admin changes foofile.txt to s1:c0.c1023
	$SECADM chcon -l s1:c0.c1023 $TESTDIR/foofile.txt
	$SYSADM ls -lZ $TESTDIR
	# bob (s1:c0.c255) CAN NOT write to foofile.txt (s1:c0.c1023)
	sleep 1
	$BOB dd if=/dev/zero of=$TESTDIR2/foofile.txt <<< "some text" && error "bob not blocked"
	ausearch -ts now  -m avc -sv no | grep comm=mdt

	# bob (c1:c0.c255) CAN NOT read foofile.txt (s1:c0.c1023)
	sleep 1
	$BOB cat $TESTDIR2/foofile.txt | grep "some text" && error "bob can read file"
	ausearch -ts now  -m avc -sv no | grep comm=mdt

	# allice (c2:c0.c1023) Can read foofile.txt (s1:c0.c1023)
	$ALICE cat $TESTDIR/foofile.txt | grep "some text" || error "alice can't read file"
	# allice (c2.c0.c1023) CAN NOT write to foofile.txt (s1:c0.1023)
	sleep 1
	$ALICE dd of=$TESTDIR/foofile.txt <<< "another text" && error "alice not blocked"
	ausearch -ts now  -m avc -sv no  | grep comm=mdt

	echo "Files with s2"
	# sec_admin changes foofile.txt to s2
	$secadm chcon -l s2:c0.c255 $TESTDIR/foofile.txt
	$sysadm ls -lZ $TESTDIR
	# bob (s1:c0.c255) CAN NOT write to foofile.txt (s2:c0.c255)
	sleep 1
	$BOB dd if=/dev/zero of=$TESTDIR2/foofile.txt <<< "some text" && error "bob not blocked"
	ausearch -ts now  -m avc -sv no  | grep comm=mdt

	# bob (s1:c0.c255) CAN NOT read foofile.txt (s2:c0.c255)
	sleep 1
	$BOB cat $TESTDIR2/foofile.txt | grep "some text" && error "bob can read file"
	ausearch -ts now  -m avc -sv no  | grep comm=mdt

	# alice (s2:c0.c1023) can read foofile.txt (s2:c0.c255) 
	$ALICE cat $TESTDIR/foofile.txt | grep "some text" || error "alice can't read file"

	# alice (s2:c0.c1023) CAN NOT write to foofile.txt (s2:c0.c255)
	sleep 1
	$ALICE dd of=$TESTDIR/foofile.txt <<< "another text" &&  error "alice can write"
	ausearch -ts now  -m avc -sv no  | grep comm=mdt

	echo "Copy files"
	# sec_admin change foofile to s1
	$secadm chcon -l s1:c0.c100 $TESTDIR/foofile.txt
	$sysadm ls -lZ $TESTDIR
	# copy security context from foofile.txt to fooflle2.txt
	$BOB cp --preserve=xattr $TESTDIR2/foofile.txt $TESTDIR2/foofile2.txt
	# set user's label to foofile2.txt
	$BOB cp $TESTDIR2/foofile.txt $TESTDIR2/foofile3.txt

	$SYSADM ls -lZ $TESTDIR
	echo "Finished successfully"
}
run_test 2 "Basic MLS tests"

test_3 () {
	SYSADM="runcon sysadm_u:sysadm_r:sysadm_t:s0-s15:c0.c1023" 
	ALICE="runcon staff_u:staff_r:staff_t:s2:c0.c1023"
	BOB="runcon staff_u:staff_r:staff_t:s1:c0.c255"
	SECADM="runcon root:secadm_r:secadm_t:s0-s15:c0.c1023"
	echo "sysadm:"; $SYSADM id -Z
	echo "alice:"; $ALICE id -Z
	echo "bob:"; $BOB id -Z
	echo "secadm:"; $SECADM id -Z

	chmod 777 $DIR
	umask 000
	
	TESTDIR=$DIR/$tdir
	TESTDIR2=$MOUNT2/$tdir
	$SYSADM rm -fR $TESTDIR
	$SYSADM mkdir $TESTDIR
	$SYSADM chcon user_u:object_r:user_home_dir_t:s2:c0.c1023 $TESTDIR2

	echo "alice create file"
	# alice (s2:c0.c1023) creates foofile.txt (s2:c0.1023)
	$SECADM ls -lZ $TESTDIR/foofile.txt
	$ALICE dd of=$TESTDIR/foofile.txt <<< "some text" || error "can't create file"

	echo "bob should not read this file"
	# bob (s1:c0.c255)  CAN NOT read foofile.txt (s2:c0.1023) 
	$BOB ls -lZ $TESTDIR2/foofile.txt | grep "foofile.txt" && error "bob can get attrs"

	# and SHOULD NOT read just after alice red it on the same mount
	echo "but after alice access this file"
	$ALICE ls -lZ $TESTDIR2/foofile.txt | grep "foofile.txt" || error "alice can't get attrs"
	echo "bob can read it (if bug exists)"
	# comment next string and this test wiil not be bassed without fix 
	cancel_lru_locks mdc
	$BOB ls -lZ  $TESTDIR2/foofile.txt | grep "foofile.txt" && error "bob can get attrs"

	echo "Finished successfully"
}
run_test 3 "Client cache allows to pass mds security checks"

complete $(basename $0) $SECONDS
# check_and_cleanup_lustre
exit_status
