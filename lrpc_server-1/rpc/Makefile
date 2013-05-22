CC=g++
CFLAGS=-I.
SOBJ = CipherKey.o Cipher.o NullCipher.o SSL_Cipher.o openssl.o Interface.o ConfigVar.o base64.o KeyGenerator.o
LIBS=-lpthread -lssl -lz  -lrlog  -L/usr/lib 

%.o: %.cpp %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

key: $(SOBJ) $(OBJ)
	g++ -DHAVE_CONFIG_H -I. -I.. -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=26 -D__STDC_FORMAT_MACROS -DRLOG_COMPONENT="makekey" -I/usr/include -I/usr/include -W -Wall -Wpointer-arith -Wwrite-strings -g -O2 $^ $(CFLAGS) $(LIBS)

clean:
	rm -f *.o *.log

