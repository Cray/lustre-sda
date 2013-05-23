#!/bin/bash

#################################################################
# This script will run n instances of fileop utility to test    #
# mkdir, chdir, rmdir, create, write, close, stat, open, read,  #
# access, chmod, readdir, link, unlink, delete system calls 	#
#################################################################

date

echo "Sanity script ....is running"
echo "Wait for few minutes for the script to complete its processing"

INSTCOUNT=1
FILESIZE="1k 64k 128k"
usage="usage: $0 -i <instance count> -s <filesizes in > or $0 "

while getopts ":hi:s:" option
do
  case "$option" in
    h) echo "$usage"
       exit
       ;;
    i) INSTCOUNT=$OPTARG
       ;;
    s) FILESIZE="$OPTARG"
       ;;
    ?) echo "illegal option: $OPTARG" >&2
       echo "$usage" >&2
       exit 1
       ;;
  esac
done


mkdir -p sanity_test/
cd sanity_test/

for((j=0;j<$INSTCOUNT;j++))
do
   mkdir -p $j
   cd $j
   for i in $FILESIZE
   do
      mkdir -p $i
      cd $i
      fileop -f 10 -s $i -t > fileop_$i.log_$(date +%d-%m-%Y-%H:%M:%S) 2>&1 &
      cd -
   done
   cd ..
 CurrentDir=`pwd`
done

while (ps -a | grep -q "fileop") ; do
   echo -n "." 
   sleep 0.1
done

echo 
echo "Script has completed its process !!!"
echo "Log files are generated in $HOME/sanity_test/"

cp -r $CurrentDir $HOME/sanity_test/

grep -nri "failed" $HOME/sanity_test/

