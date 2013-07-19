#!/bin/bash
# Description: Delete audit logs more that 5 years old in audit log directory.
# Author: Sumit Rai
# Email : sumit_rai@xyratex.com

AUDITLOG_DIR="/var/log/audit"

# Get Current Epoch time
CUR_TIME=$(date +%s)

# Time in seconds after which Log files older than this time are deleted.
# By default set to 5 years. (5*365*24*60*60)
MAX_TIME_LIMIT=157680000

# Loop through all the log file and delete any log files older than 5 years.
for logFile in $(ls -l $AUDITLOG_DIR | egrep 'audit.log.[0-9]+' | sort | awk '{ print $NF }')
do
    # Get the last modification Epoch time
    LAST_MOD_TIME=$(stat -c %Y $AUDITLOG_DIR/$logFile)
    difference=$(expr $CUR_TIME - $LAST_MOD_TIME)
    if [ $difference -ge $MAX_TIME_LIMIT ]
    then
	rm $AUDITLOG_DIR/$logFile
    fi
done