#This Makefile will run the Makefile in app/TCGCmdLineTool.


TARGET1:
	cd app/TCGCmdLineTool; make

all: $(TARGET1)


install:
		install -m 0755 -d /home/rpmbuild/rpm/bin/SED
		cd app/TCGCmdLineTool; install -m 0755 exec /home/rpmbuild/rpm/bin/SED
		cd lib/linux; install -m 0755 dtad.a /home/rpmbuild/rpm/bin/SED
		cd lib/linux; install -m 0755 tcgi.a /home/rpmbuild/rpm/bin/SED


    .PHONY: install

clean:
		cd app/TCGCmdLineTool; make clean;
