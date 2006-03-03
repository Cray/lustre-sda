Summary: Lustre IO test kit
Name: lustre-iokit
Vendor: Scali AS
URL: http://www.scali.com/
Version: 0.12.0
Release: 1
License: LGPL
Group: Applications/System
Source0: %{name}-%{version}-%{release}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

%description
Lustre IO-Kit is a collection of benchmark-tools for a cluster with
the lustre filesystem.

Currently only a Object Block Device-survey are included, but the kit may
be extended with blockdevice- and filesystem- survey in the future.

Copyright (c) 2005 Scali AS. All Rights Reserved.


Contact :
Scali AS
Olaf Helsets vei 6, P.O Box 150, Oppsal
N-0619 Oslo
NORWAY

Technical support : support@scali.com
Licensing support : license@scali.com
http://www.scali.com


%prep
%setup -q -n lustre-iokit

%build
python setup.py build

%install
rm -rf $RPM_BUILD_ROOT
python setup.py install --root $RPM_BUILD_ROOT

%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
/usr/bin/*
/usr/lib*/python*/site-packages/*
%doc /usr/share/lustre-iokit*


%changelog
* Mon Sep 19 2005 Ragnar Kjorstad <rk@scali.com> v0.12
- Build fixes
* Wed Apr  6 2005 Ragnar Kjorstad <rk@scali.com> v0.11-1
- Compability-fixes with python2.2 (rhel3)
* Fri Apr  1 2005 Ragnar Kjorstad <rk@scali.com> v0.10-2
- Makefile-fixes for rhel3-x86_64
* Mon Feb 21 2005 Ragnar Kjorstad <rk@scali.com>
- Initial build.

