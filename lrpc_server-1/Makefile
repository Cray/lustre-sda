CC=g++
CFLAGS=-I. -I rpc/
SOBJ =   lrpc_server.o lrpc_misc_server.o ldap_connection.o lrpc_ldap.o ConfFileReader.o rpc/CipherKey.o rpc/Cipher.o rpc/NullCipher.o rpc/SSL_Cipher.o rpc/openssl.o rpc/Interface.o rpc/ConfigVar.o rpc/base64.o rpc/KeyGenerator.o 
LIBS=-lgssapi_krb5 -lpthread -lgssrpc -lldap -lcrypto -lssl -lz  -lrlog -lconfig++

%.o: %.c $(DEPS)
	$(CC) -c -Wall -pg -w -fpermissive -lconfig++ -o $@ $< $(CFLAGS)

server: $(SOBJ) $(OBJ)
	g++  -g -Wall -pg -w -fpermissive -o lserver $^ $(CFLAGS) $(LIBS)

clean:
	rm -f lserver lclient *.o rpc/*.o
 
