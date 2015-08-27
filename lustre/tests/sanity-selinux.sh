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
	echo "changing context to s1"
	chcon "root:object_r:file_t:s1" $DIR/$tfile-f2
	sync; sleep 3; sync
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

complete $(basename $0) $SECONDS
# check_and_cleanup_lustre
exit_status
