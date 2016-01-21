Name:       pkgmgr-server
Summary:    Packager Manager server package
Version:    0.3.37
Release:    1
Group:      Application Framework/Package Management
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source1001: %{name}.manifest
BuildRequires:  cmake
BuildRequires:  unzip
BuildRequires:  gettext-tools
BuildRequires:  pkgconfig(dbus-glib-1)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(gio-2.0)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(bundle)
BuildRequires:  pkgconfig(pkgmgr-info)
BuildRequires:  pkgconfig(iniparser)
BuildRequires:  pkgconfig(libtzplatform-config)
BuildRequires:  pkgconfig(security-manager)
BuildRequires:  pkgconfig(xdgmime)
BuildRequires:  pkgconfig(db-util)
BuildRequires:  pkgconfig(libsmack)
BuildRequires:  pkgconfig(pkgmgr)
BuildRequires:  pkgconfig(drm-service-core-tizen)
BuildRequires:  pkgconfig(sqlite3)
BuildRequires:  pkgmgr-info-parser-devel
BuildRequires:  pkgmgr-info-parser
BuildRequires:  fdupes

%description
Packager Manager server package for packaging

%prep
%setup -q
cp %{SOURCE1001} .

%build
sqlite3 blacklist.db < ./blacklist.sql

%cmake . -DLOCAL_STATE_DIR=%{_localstatedir}

%__make %{?_smp_mflags}

%install
%make_install

mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}
mkdir -p %{buildroot}%{_sysconfdir}/package-manager/server

mkdir -p %{buildroot}%{_localstatedir}/package-manager/
install -m 0600 blacklist.db %{buildroot}%{_localstatedir}/package-manager/

%fdupes %{buildroot}

%post
/sbin/ldconfig

%files
%manifest %{name}.manifest
%defattr(-,root,root,-)
%{_datadir}/dbus-1/system-services/org.tizen.pkgmgr.service
%config %{_sysconfdir}/dbus-1/system.d/org.tizen.pkgmgr.conf
%{_bindir}/pkgmgr-server
%{_sysconfdir}/package-manager/server
%config(noreplace) %{_localstatedir}/package-manager/blacklist.db
%exclude %{_sysconfdir}/package-manager/server/queue_status
/usr/share/license/%{name}
