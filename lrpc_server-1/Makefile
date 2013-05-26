CC=g++
CFLAGS=-I. -I rpc/
SOBJ =  lrpc_server.o lrpc_misc_server.o ldap_connection.o lrpc_ldap.o ConfFileReader.o rpc/CipherKey.o rpc/Cipher.o rpc/NullCipher.o rpc/SSL_Cipher.o rpc/openssl.o rpc/Interface.o rpc/ConfigVar.o rpc/base64.o rpc/KeyGenerator.o
LIBS=-lgssapi_krb5 -lpthread -lgssrpc -lldap -lcrypto -lssl -lz  -lrlog -lconfig++

%.o: %.c $(DEPS)
	$(CC) -c -Wall -pg -w -fpermissive -o  $@ $< $(CFLAGS)

server: $(SOBJ) $(OBJ)
	g++  -g -Wall -pg -w -fpermissive -o lserver $^ $(CFLAGS) $(LIBS)

clean:
	rm -f lserver lclient *.o rpc/*.o
 
rpm: 	
	#build tree
	mkdir -p $(HOME)/rpm/{BUILD,RPMS,RPMS/x86_64,RPMS/noarch,SOURCES,SPECS,SRPMS,tmp}

	#backup .rpmmacros file
	if [ -f  "${HOME}/.rpmmacros" ]; then \
		cp ${HOME}/.rpmmacros  ${HOME}/rpm/tmp/ ;\
	fi

	#make rpmbuild to use newly build tree 
	echo "%_topdir $(HOME)/rpm" > $(HOME)/.rpmmacros
	echo "%_tmppath $(HOME)/rpm/tmp" >> $(HOME)/.rpmmacros

	#place .spec and tar ball in build tree
	install -m 0777 lrserver.spec $(HOME)/rpm/SPECS
	tar -cvzf $(HOME)/rpm/tmp/lrpc_server-1.tar.gz ../lrpc_server-1 >/dev/null
	install -m 0755 $(HOME)/rpm/tmp/lrpc_server-1.tar.gz $(HOME)/rpm/SOURCES/

	#build binary tree
	rpmbuild -ba --rmsource lrserver.spec

	#restore .rpmmacros file
	if [ -f  "${HOME}/rpm/tmp/.rpmmacros" ]; then \
		cp ${HOME}/rpm/tmp/.rpmmacros  ${HOME}/.rpmmacros ;\
	else \
		rm ${HOME}/.rpmmacros ; \
	fi

	#cleanup
	rm -rf $(HOME)/rpm/BUILD/ $(HOME)/rpm/SOURCES/lrpc_server-1.tar.gz $(HOME)/rpm/SPECS/ $(HOME)/rpm/tmp/
