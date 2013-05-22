
SRCDIR = dti
OBJDIR = ../lib/linux
LIBDIR = ../lib/linux
BINDIR = ../bin/linux
PLFDIR = $(SRCDIR)/platform/linux32
CMPDIR = $(SRCDIR)/compilers/gcc

INCLIB = -Idta/ -I$(SRCDIR)/crypto/
DEPLIB = $(LIBDIR)/dtad.a

CPPFLAG = -Wall $(INCLIB)

OBJECTS = apdumanager.o dti.o sci.o sciinternal.o seacostasks.o userfunctions.o

HEADER = #$(SRCDIR)/dta.hpp \
         $(SRCDIR)/dti.hpp

sci.a: $(OBJECTS)
	ar -cvq $(LIBDIR)/sci.a $(OBJECTS)
	mv $(OBJECTS) $(OBJDIR)

apdumanager.o: $(HEADER) $(SRCDIR)/apdumanager.cpp
	g++ -c $(CPPFLAG) $(HEADER) $(SRCDIR)/apdumanager.cpp

dti.o: $(HEADER) $(SRCDIR)/dti.cpp
	g++ -c $(CPPFLAG) $(HEADER) $(SRCDIR)/dti.cpp

sci.o: $(HEADER) $(SRCDIR)/sci.cpp
	g++ -c $(CPPFLAG) $(HEADER) $(SRCDIR)/sci.cpp

sciinternal.o: $(HEADER) $(SRCDIR)/sciinternal.cpp
	g++ -c $(CPPFLAG) $(HEADER) $(SRCDIR)/sciinternal.cpp

seacostasks.o: $(HEADER) $(SRCDIR)/seacostasks.cpp
	g++ -c $(CPPFLAG) $(HEADER) $(SRCDIR)/seacostasks.cpp

userfunctions.o: $(HEADER) $(SRCDIR)/helper/userfunctions.cpp
	g++ -c $(CPPFLAG) $(HEADER) $(SRCDIR)/helper/userfunctions.cpp

.PHONY: clean
clean:
	rm -f $(LIBDIR)/sci.a
	rm -f $(OBJDIR)/apdumanager.o
	rm -f $(OBJDIR)/dti.o
	rm -f $(OBJDIR)/sci.o
	rm -f $(OBJDIR)/sciinternal.o
	rm -f $(OBJDIR)/seacostasks.o
	rm -f $(OBJDIR)/userfunctions.o
