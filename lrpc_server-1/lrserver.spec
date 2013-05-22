Summary: lserver production version 1-1
Name:lrpc_server
Version:1
Release:        1%{?dist}
License:GPL
Group: Development/System
Source:%{name}-%{version}.tar.gz
BuildRoot:/tmp
%description
lserver

%prep
%setup -q

%build
make
%define debug_package %{nil}

%install
install -m 0755 -D lrpc_server.o $RPM_BUILD_ROOT/lrpc_RPM/bin/lrpc/lrpc_server.o
install -m 0755 lrpc_misc_server.o $RPM_BUILD_ROOT/lrpc_RPM/bin/lrpc/lrpc_misc_server.o
install -m 0755 lrpc_ldap.o $RPM_BUILD_ROOT/lrpc_RPM/bin/lrpc/lrpc_ldap.o
install -m 0755 ldap_connection.o $RPM_BUILD_ROOT/lrpc_RPM/bin/lrpc/ldap_connection.o
install -m 0755 -D rpc/Interface.o $RPM_BUILD_ROOT/lrpc_RPM/bin/lrpc/rpc/Interface.o
install -m 0755 rpc/NullCipher.o $RPM_BUILD_ROOT/lrpc_RPM/bin/lrpc/rpc/NullCipher.o
install -m 0755 rpc/base64.o $RPM_BUILD_ROOT/lrpc_RPM/bin/lrpc/rpc/base64.o
install -m 0755 rpc/KeyGenerator.o $RPM_BUILD_ROOT/lrpc_RPM/bin/lrpc/rpc/KeyGenerator.o
install -m 0755 rpc/openssl.o $RPM_BUILD_ROOT/lrpc_RPM/bin/lrpc/rpc/openssl.o
install -m 0755 rpc/ConfigVar.o  $RPM_BUILD_ROOT/lrpc_RPM/bin/lrpc/rpc/ConfigVar.o
install -m 0755 rpc/CipherKey.o  $RPM_BUILD_ROOT/lrpc_RPM/bin/lrpc/rpc/CipherKey.o
install -m 0755 rpc/Cipher.o  $RPM_BUILD_ROOT/lrpc_RPM/bin/lrpc/rpc/Cipher.o
install -m 0755 rpc/SSL_Cipher.o  $RPM_BUILD_ROOT/lrpc_RPM/bin/lrpc/rpc/SSL_Cipher.o
install -m 0755 lserver $RPM_BUILD_ROOT/lrpc_RPM/bin/lrpc/lserver

%post
ln -s /lrpc_RPM/bin/lrpc/lserver /usr/local/bin/cal_lserver

%files
%defattr(-,root,root,-)

%dir
/lrpc_RPM
