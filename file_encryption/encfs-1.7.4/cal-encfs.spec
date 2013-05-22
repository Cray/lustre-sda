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
rm -rf $RPM_BUILD_ROOT
%make_install

%files
/usr/
%defattr(-,root,root,-)

%dir
