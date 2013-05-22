#This Makefile will run 2 makefiles in ../../dtl
#make.dtl.tcgi_working and make.dtl.dtad_working
# And will compille the TCGDaemon.cpp and TCGUsage.cpp files to generate executable



TARGET: TARGET1 TARGET2 TARGET3

TARGET1:
		cd ../../dtl; make -f make.dtl.tcgi_working

TARGET2:
		cd ../../dtl; make -f make.dtl.dtad_working

TARGET3:
		 g++ -g -o exec TCGDaemon.cpp TCGUsage.cpp ../../dtl/dti/tcg/Sample_HelperFunc_Wrappers/TCGDrive_Console.cpp -I ../../dtl/dta/ -I ../../dtl/dti/ ../../lib/linux/dtad.a ../../lib/linux/tcgi.a -lpthread

all: $(TARGET)

clean:
		rm -f exec;
		cd ../../dtl; make clean -f make.dtl.tcgi_working;
		cd ../../dtl; make clean -f make.dtl.dtad_working;





