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

test_1() {
	printf $PCONTEXTDEF > /proc/self/attr/current

	echo "test" > $DIR/$tfile
	setfattr -n user.attr -v val $DIR/$file

	do_facet mds1 setenforce 1
	cat $DIR/$tfile || echo "no access to the file"
	do_facet mds1 setenforce 0

	chcon -l s15 $DIR/$tfile

	do_facet mds1 setenforce 1
	runcon -l s0 cat $DIR/$tfile && echo "have access to the file"
	runcon -l s0 unlink $DIR/$tfile && echo "managed to unlink"
	runcon -l s0 stat $DIR/$tfile && echo "managed to stat"
	runcon -l s0 touch $DIR/$tfile && echo "managed to setattr"
	runcon -l s0 ls -salZ $DIR | grep $tfile || echo "failed to list"
	runcon -l s0 multiop $DIR/$tfile N $DIR/${tfile}2 &&
		echo "managed to rename"
	runcon -l s0 getfattr -n user.attr $DIR/$tfile &&
		echo "managed to getxattr"
	runcon -l s0 setfattr -n user.attr -v val $DIR/$tfile &&
		echo "managed to setxattr"
	runcon -l s0 getfattr -d $DIR/$tfile && echo "managed to listxattr"
	do_facet mds1 setenforce 0

	rm -f $DIR/$tfile
}
run_test 1 "basic server tests"

complete $(basename $0) $SECONDS
check_and_cleanup_lustre
exit_status
