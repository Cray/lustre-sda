Summary: Encfs production version 1.7.4-1
Name:encfs
Version:1.7.4
Release:        1%{?dist}
License:GPL
Group: Development/System
Source:%{name}-%{version}.tar.gz
BuildRoot:/tmp/
%description
Modified encfs-1.7.4 for kerberosation and using encrytion key per file.

%prep
%setup -q

%build
make
%define debug_package %{nil}

%install
mkdir -p  $RPM_BUILD_ROOT/etc/
install -m 0644 encfs.conf $RPM_BUILD_ROOT/etc/encfs.conf

%make_install

%post

%postun
rm -f /etc/encfs.conf

%files
/usr/

%defattr(-,root,root,-)

%dir
/etc
