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
mkdir -p  $RPM_BUILD_ROOT/usr/local/bin/
mkdir -p  $RPM_BUILD_ROOT/etc/
install -m 0755 lserver $RPM_BUILD_ROOT/usr/local/bin/lserver
install -m 0644 lrpc.conf $RPM_BUILD_ROOT/etc/lrpc.conf

%post

%postun
rm -f /etc/lrpc.conf

%files
%defattr(-,root,root,-)

%dir
/usr
/etc
