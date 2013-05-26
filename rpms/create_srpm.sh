#!/bin/bash
#Usage: sh create_srpm.sh <dirname> <specfilename> 
#Usage for encfs: sh create_srpm.sh encfs-1.7.4 cal_encfs 
#Usage for lserver: sh create_srpm.sh lrpc_server-1 lrserver.spec  

 if [ $# -ne 2 ]; then
	echo Use: to create srpms
	echo Note: This script will create srpm in $HOME/rpm/SRPMS/
	echo "sh create_srpm.sh <dirname> <specfilename>"
	echo example:
	echo Usage for encfs: sh create_srpm.sh encfs-1.7.4 cal-encfs.spec
	echo Usage for lserver: sh create_srpm.sh lrpc_server-1 lrserver.spec
	exit 1
 fi

 set -x

 cd ..

 mkdir -p ${HOME}/rpm/{BUILD,RPMS,RPMS/x86_64,RPMS/noarch,SOURCES,SPECS,SRPMS,tmp}

 #backup .rpmmacros file
 if [ -f  "${HOME}/.rpmmacros" ]; then 
          cp ${HOME}/.rpmmacros  ${HOME}/rpm/tmp/ 
 fi
 
 #make rpmbuild to use newly build tree
 echo "%_topdir ${HOME}/rpm" > ${HOME}/.rpmmacros
 echo "%_tmppath ${HOME}/rpm/tmp" >> ${HOME}/.rpmmacros


 tar -cvzf  $1.tar.gz $1/ > /dev/null
 rm -f ${HOME}/rpm/SOURCES/*
 cp $1.tar.gz ${HOME}/rpm/SOURCES/
 ls -lr ${HOME}/rpm/SOURCES/
 date
 cd $1
 cp $2 ${HOME}/rpm/SPECS/$2 
 rpmbuild -bs ${HOME}/rpm/SPECS/$2

 #restore .rpmmacros file
 if [ -f  "${HOME}/rpm/tmp/.rpmmacros" ]; then 
         cp ${HOME}/rpm/tmp/.rpmmacros  ${HOME}/.rpmmacros 
 else 
         rm  ${HOME}/.rpmmacros 
 fi
