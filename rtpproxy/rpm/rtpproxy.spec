%define RPMName         rtpproxy
%define RPMVersion      0.001
%define RPMRelease      5

%define ITCGUI      	%{RPMName}-%{RPMVersion}

#disable debug packages
%define debug_package %{nil}

Summary: IskraTel Graphical User Interface
Name: %{RPMName}
Version: %{RPMVersion}
Release: %{RPMRelease}
Group: Applications/Engineering
License: Iskratel Ltd.
Packager: Tomaz Buh, <buh@iskratel.si>
#Requires: dpdk-devel >= 0
#Requires: make >= 3
#Requires: tar >= 1
#Requires: initscripts >= 7
Source: %{RPMName}-%{RPMVersion}.tar.xz
%description
DPDK based rtp proxy. 
%prep
%setup
%build
export RTE_SDK=/usr/share/dpdk/
export RTE_TARGET=x86_64-default-linuxapp-gcc
make
%install
mkdir -p %{buildroot}/usr/local/bin
cp build/app/rtpproxy %{buildroot}/usr/local/bin
cp dpdkenv %{buildroot}/usr/local/bin
%clean
rm -rf  %_builddir/%buildsubdir
rm -rf %buildroot
%pre
%post
%preun
%postun
%files
%defattr(-,root,root)
/usr/local/bin/rtpproxy
/usr/local/bin/dpdkenv
%changelog
* Thu May 09 2017 Tomaz Buh, ITWEV, Tel: 3096, <buh@iskratel.si>
- Initial package.

