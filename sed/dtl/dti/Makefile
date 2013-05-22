
SRCDIR = dti
OBJDIR = ../lib/linux
LIBDIR = ../lib/linux
BINDIR = ../bin/linux
PLFDIR = $(SRCDIR)/platform/linux32
##CMPDIR = $(SRCDIR)/compilers/gcc

INCLIB = -Idta/ -I$(SRCDIR)/crypto/
DEPLIB = $(LIBDIR)/dtad.a

CPPFLAG = -Wall $(INCLIB)

OBJECTS = dti.o ieee1667i.o tcgsilo.o

HEADER = #$(PLFDIR)/Pcommon.h \
         #$(CMPDIR)/Xcommon.h \
         #$(SRCDIR)/common.h \
         $(SRCDIR)/errors.h \
         $(SRCDIR)/dta.hpp \
         $(SRCDIR)/dti.hpp

ieee1667i.a: $(OBJECTS)
	ar -cvq $(LIBDIR)/ieee1667i.a $(OBJECTS)
	mv $(OBJECTS) $(OBJDIR) 

dti.o: $(HEADER) $(SRCDIR)/dti.cpp
	g++ -c $(CPPFLAG) $(HEADER) $(SRCDIR)/dti.cpp

ieee1667i.o: $(HEADER) $(SRCDIR)/ieee1667i.cpp	
	g++ -c -O2 $(CPPFLAG) $(HEADER) $(SRCDIR)/ieee1667i.cpp

##passwordsilo.o: $(HEADER) $(SRCDIR)/passwordsilo.cpp
##	g++ -c $(CPPFLAG) $(HEADER) $(SRCDIR)/passwordsilo.cpp

tcgsilo.o: $(HEADER) $(SRCDIR)/tcgsilo.cpp
	g++ -c $(CPPFLAG) $(HEADER) $(SRCDIR)/tcgsilo.cpp


.PHONY: clean
clean:
	rm -f $(LIBDIR)/ieee1667i.a
	rm -f $(OBJDIR)/dti.o
	rm -f $(OBJDIR)/ieee1667i.o
	rm -f $(OBJDIR)/passwordsilo.o
	rm -f $(OBJDIR)/tcgsilo.o
