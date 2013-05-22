	#!/bin/bash

	#################################################################
	# This script will firstly run make file.                       #
	# After that it will execute the ./exec which is your executable#
	#                                                               #
	#################################################################

	date

        echo "Sanity script ....is running"
        echo "Wait for few minutes for the script to complete its processing"

 	echo "======================================================================================"

	make

        echo "======================================================================================"

	ls -la ./exec

	date

	cd /home/sid/seagateSDKProd/app/TCGCmdLineTool

	./exec --Quiet LR

	cd /home/sid/NEW_COPY/seagateSDKProd/app/TCGCmdLineTool

	echo "Performing UNLOCK OPERATION ON BAND 1"

	echo "======================================================================================"

	read dummy_var

        ./exec

	echo "======================================================================================"

	read dummy_var

	echo "======================================================================================"

	cd /home/sid/seagateSDKProd/app/TCGCmdLineTool

	./exec --Quiet LR

	echo "======================================================================================"

	cd /home/sid/NEW_COPY/seagateSDKProd/app/TCGCmdLineTool

	echo "======================================================================================"

	echo "make clean"

	echo "======================================================================================"

	make clean

	ls ../../lib/linux/




