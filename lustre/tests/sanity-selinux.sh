#!/bin/bash
#
# Test basic functionality of SELinux support.
#

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

assert_DIR
rm -rf $DIR/[df][0-9]*

$LCTL dl | grep mdt &&
	error "client node should not be running MDT for this test"
DCONTEXT=`stat -c %C /tmp`
echo "using dir context $DCONTEXT"
chcon $DCONTEXT $DIR

PCONTEXTDEF="root:staff_r:staff_t:s0-s15:c0.c1023"
SCONTEXTDEF="root:sysadm_r:sysadm_t:s0-s15:c0.c1023"

sestatus | egrep "Current mode:[[:space:]]*permissive" || error "client non-permissive"
sestatus | egrep "Policy from config file:[[:space:]]*mls" || error "client non-mls"

do_facet mds1 'sestatus | egrep "Current mode:[[:space:]]*permissive"' || error "mds non-permissive"
do_facet mds1 'sestatus | egrep "Policy from config file:[[:space:]]*mls"' || error "mds non-mls"

cleanup_unenforce() {
	do_facet mds1 setenforce 0
}

test_1() {
	printf $PCONTEXTDEF > /proc/self/attr/current

	echo "test" > $DIR/$tfile
	setfattr -n user.attr -v val $DIR/$file

	trap cleanup_unenforce EXIT

	do_facet mds1 setenforce 1
	echo "*** check open & read for s0 file from s0 (should succeed)"
	runcon -l s0 cat $DIR/$tfile	|| error "no access to the file"
	echo "*** check stat for s0 file from s0 (should succeed)"
	runcon -l s0 stat $DIR/$tfile	|| error "failed to stat"
	echo "*** check setattr for s0 file from s0 (should succeed)"
	runcon -l s0 touch $DIR/$tfile	|| error "failed to setattr"
	echo "*** check getxattr for s0 file from s0 (should succeed)"
	runcon -l s0 getfattr -n user.attr $DIR/$tfile ||
					   error "failed to getxattr"
	echo "*** check setxattr for s0 file from s0 (should succeed)"
	runcon -l s0 setfattr -n user.attr -v val $DIR/$tfile ||
					   error "failed to setxattr"
	echo "*** check lsxattr for s0 file from s0 (should succeed)"
	runcon -l s0 getfattr -d $DIR/$tfile ||
					   error "failed to listxattr"
	echo "*** check rename for s0 file from s0 (should succeed)"
	runcon -l s0 multiop $DIR/$tfile N $DIR/${tfile}2 ||
					   error "failed to rename"
	echo "*** check unlink for s0 file from s0 (should succeed)"
	runcon -l s0 unlink $DIR/${tfile}2 || error "failed to unlink"

	do_facet mds1 setenforce 0

	echo "test" > $DIR/$tfile
	setfattr -n user.attr -v val $DIR/$file

	chcon -l s15 $DIR/$tfile

	do_facet mds1 setenforce 1
	echo "*** check open & read for s15 file from s0 (should fail)"
	runcon -l s0 cat $DIR/$tfile	&& error "have access to the file"
	echo "*** check unlink for s15 file from s0 (should fail)"
	runcon -l s0 unlink $DIR/$tfile && error "managed to unlink"
	echo "*** check stat for s15 file from s0 (should fail)"
	runcon -l s0 stat $DIR/$tfile	&& error "managed to stat"
	echo "*** check setattr for s15 file from s0 (should fail)"
	runcon -l s0 touch $DIR/$tfile	&& error "managed to setattr"
	echo "*** check readdir for s15 file from s0 (should fail)"
	runcon -l s0 ls -salZ $DIR | grep $tfile ||
					   error "failed to list"
	echo "*** check rename for s15 file from s0 (should fail)"
	runcon -l s0 multiop $DIR/$tfile N $DIR/${tfile}2 &&
					   error "managed to rename"
	echo "*** check getxattr for s15 file from s0 (should fail)"
	runcon -l s0 getfattr -n user.attr $DIR/$tfile &&
					   error "managed to getxattr"
	echo "*** check setxattr for s15 file from s0 (should fail)"
	runcon -l s0 setfattr -n user.attr -v val $DIR/$tfile &&
					   error "managed to setxattr"
	echo "*** check lsxattr for s15 file from s0 (should fail)"
	runcon -l s0 getfattr -d $DIR/$tfile &&
					   error "managed to listxattr"
	cleanup_unenforce

	rm -f $DIR/$tfile
}
run_test 1 "basic server tests"

run_as_bob() {
	runcon -l s1:c0.c255 $@
}

run_as_alice() {
	runcon -l s2:c0.c1023 $@
}

test_2() {
	printf $PCONTEXTDEF > /proc/self/attr/current
	chcon -l s1:c0.c255 $DIR

	trap cleanup_unenforce EXIT

	do_facet mds1 setenforce 1
	echo "*** Bob (s1:c0.c255) creates $tfile (s1:c0.c255)"
	run_as_bob   touch $DIR/$tfile || error "bob should create a file"
	echo "*** Bob (s1:c0.c255) can write to $tfile (s1:c0.c255)"
	run_as_bob   dd if=/dev/zero of=$DIR/$tfile count=1 conv=notrunc || error "bob should be able to write to a file"
	echo "*** Bob (s1:c0.c255) can read from $tfile (s1:c0.c255)"
	run_as_bob   dd if=$DIR/$tfile of=/dev/zero count=1 || error "bob should be able to read a file"
	echo "*** Alice (s2:c0.c1023) can read from $tfile (s1:c0.c255)"
	run_as_alice dd if=$DIR/$tfile of=/dev/zero count=1 || error "alice should be able to read a file"
	echo "*** Alice (s2:c0.c1023) cannot write to $tfile (s1:c0.c255)"
	run_as_alice dd if=/dev/zero of=$DIR/$tfile count=1 conv=notrunc && error "alice should not be able to write to a file"
	do_facet mds1 setenforce 0

	chcon -l s1:c0.c1023 $DIR/$tfile

	do_facet mds1 setenforce 1
	echo "*** Bob (s1:c0.c255) cannot write to $tfile (s1:c0.c1023)"
	run_as_bob   dd if=/dev/zero of=$DIR/$tfile count=1 conv=notrunc && error "bob should not be able to write to a file"
	echo "*** Bob (s1:c0.c255) cannot read from $tfile (s1:c0.c1023)"
	run_as_bob   dd if=$DIR/$tfile of=/dev/zero count=1 && error "bob should not be able to read a file"
	echo "*** Alice (s2:c0.c1023) can read from $tfile (s1:c0.c1023)"
	run_as_alice dd if=$DIR/$tfile of=/dev/zero count=1 || error "alice should be able to read a file"
	echo "*** Alice (s2:c0.c1023) cannot write to $tfile (s1:c0.c255)"
	run_as_alice dd if=/dev/zero of=$DIR/$tfile count=1 conv=notrunc && error "alice should not be able to write to a file"
	do_facet mds1 setenforce 0

	chcon -l s2:c0.c1023 $DIR/$tfile

	do_facet mds1 setenforce 1
	echo "*** Bob (s1:c0.c255) cannot write to $tfile (s2:c0.c1023)"
	run_as_bob   dd if=/dev/zero of=$DIR/$tfile count=1 conv=notrunc && error "bob should not be able to write to a file"
	echo "*** Bob (s1:c0.c255) cannot read from $tfile (s2:c0.c1023)"
	run_as_bob   dd if=$DIR/$tfile of=/dev/zero count=1 && error "bob should not be able to read a file"
	echo "*** Alice (s2:c0.c1023) can read from $tfile (s2:c0.c1023)"
	run_as_alice dd if=$DIR/$tfile of=/dev/zero count=1 || error "alice should be able to read a file"
	echo "*** Alice (s2:c0.c1023) can write to $tfile (s2:c0.c1023)"
	run_as_alice dd if=/dev/zero of=$DIR/$tfile count=1 conv=notrunc || error "alice should be able to write to a file"

	cleanup_unenforce

	cp --preserve=xattr $DIR/$tfile $DIR/${tfile}2
	diff <(ls -Z $DIR/$tfile | awk '{ print $4 }') <(ls -Z $DIR/${tfile}2 | awk '{print $4}') || error "different!"
	cp $DIR/${tfile}2 $DIR/${tfile}3
}
run_test 2 "pre-release demo tests (batch modee)"

test_3() {
	# 4096 Mb, 4 Gb
	local SIZE=4096
#	local ODIRECT="oflag=direct"
#	local IDIRECT="iflag=direct"

	echo "*** writing a file using using 4 MiB block from s0"
	runcon -l s0 dd if=/dev/zero of=$DIR/${tfile}1 $ODIRECT bs=4M count=$((SIZE/4))
	echo "*** writing a file using using 4 MiB block from s15"
	runcon -l s15 dd if=/dev/zero of=$DIR/${tfile}2 $ODIRECT  bs=4M count=$((SIZE/4))
	echo "*** writing a file using using 4 KiB block from s0"
	runcon -l s0 dd if=/dev/zero of=$DIR/${tfile}3 $ODIRECT bs=4K count=$((SIZE/4*1024))
	echo "*** writing a file using using 4 KiB block from s15"
	runcon -l s15 dd if=/dev/zero of=$DIR/${tfile}4 $ODIRECT bs=4K count=$((SIZE/4*1024))

	echo "*** reading a file using using 4 MiB block from s0"
	runcon -l s0 dd of=/dev/zero if=$DIR/${tfile}1 $IDIRECT bs=4M count=$((SIZE/4))
	echo "*** reading a file using using 4 MiB block from s15"
	runcon -l s15 dd of=/dev/zero if=$DIR/${tfile}2 $IDIRECT bs=4M count=$((SIZE/4))
	echo "*** reading a file using using 4 KiB block from s0"
	runcon -l s0 dd of=/dev/zero if=$DIR/${tfile}3 $IDIRECT bs=4K count=$((SIZE/4*1024))
	echo "*** reading a file using using 4 KiB block from s15"
	runcon -l s15 dd of=/dev/zero if=$DIR/${tfile}4 $IDIRECT bs=4K count=$((SIZE/4*1024))

	rm -f $DIR/${tfile}1 $DIR/${tfile}2 $DIR/${tfile}3 $DIR/${tfile}4
}
run_test 3 "performance testing"

AUDIT_REPORT="ausearch -m AVC --input-logs"

test_4() {
	local FILEFID
	local DIRFID
	trap cleanup_unenforce EXIT

	for i in `seq 0 9`; do
		touch $DIR/$tfile$i
		FILEFID[$i]=$(lfs path2fid $DIR/$tfile$i)
		chcon -l s1 $DIR/$tfile$i
	done

	do_facet mds1 semanage dontaudit off
	do_facet mds1 setenforce 1

	echo "*** unlink test"
	unlink $DIR/${tfile}0 && error "unlink should have failed"
	do_facet mds1 "$AUDIT_REPORT | tail -150 | grep -F ${FILEFID[0]} | grep remove_name" ||
		error "audit logs should have remove_name on failed unlink"

	echo "*** rename test"
	multiop $DIR/${tfile}1 N $DIR/${tfile}20 && error "rename should have failed"

	do_facet mds1 "$AUDIT_REPORT | tail -150 | grep -F ${FILEFID[1]} | grep remove_name" ||
		error "audit logs should have remove_name on failed rename"
	
	echo "*** setxattr test"
	setfattr -n user.attr -v val $DIR/${tfile}3 && error "setxattr should have failed"
	# yes, setXattr failure is recorded as setattr failure in SELinux
	do_facet mds1 "$AUDIT_REPORT | tail -150 | grep -F ${FILEFID[3]} | grep setattr" ||
		error "audit logs should have setattr on failed setxattr"

	echo "*** getxattr test"
	getfattr -n user.attr $DIR/${tfile}6 && error "getxattr should have failed"
	# yes, getXattr failure is recorded as getattr failure in SELinux
	do_facet mds1 "$AUDIT_REPORT | tail -150 | grep -F ${FILEFID[6]} | grep getattr" ||
		error "audit logs should have getattr on failed getxattr"

	echo "*** setattr test"
	touch $DIR/${tfile}4 && error "touch should have failed"
	do_facet mds1 "$AUDIT_REPORT | tail -150 | grep -F ${FILEFID[4]} | grep setattr" ||
		error "audit logs should have setattr on failed touch"

	echo "*** read test"
	cat $DIR/${tfile}6 && error "read should have failed"
	do_facet mds1 "$AUDIT_REPORT | tail -150 | grep -F ${FILEFID[6]} | grep read\ open" ||
		error "audit logs should have read/open on failed read"

	echo "*** write test"
	echo test > $DIR/${tfile}5 && error "write should have failed"
	do_facet mds1 "$AUDIT_REPORT | tail -150 | grep -F ${FILEFID[5]} | grep write\ open" ||
		error "audit logs should have write/open on failed write"

	do_facet mds1 semanage dontaudit on

	cleanup_unenforce
}
run_test 4 "audit logs testing"

complete $(basename $0) $SECONDS
check_and_cleanup_lustre
exit_status
