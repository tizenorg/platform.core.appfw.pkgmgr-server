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
BuildRequires:  pkgconfig(pkgmgr)
BuildRequires:  pkgconfig(pkgmgr-installer)
BuildRequires:  pkgconfig(drm-service-core-tizen)
BuildRequires:  pkgconfig(libgum)
BuildRequires:  pkgconfig(sqlite3)
BuildRequires:  pkgmgr-info-parser-devel
BuildRequires:  pkgmgr-info-parser
BuildRequires:  fdupes

%description
Packager Manager server package for packaging

%prep
%setup -q
cp %{SOURCE1001} .

%define run_dir /run/user
%define db_dir %{_localstatedir}/lib/package-manager
%define backend_dir %{_sysconfdir}/package-manager/backend

%build
sqlite3 restriction.db < ./restriction.sql

%cmake . -DRUN_DIR=%{run_dir} \
         -DDB_DIR=%{db_dir} \
         -DBACKEND_DIR=%{backend_dir} \
         -DUNITDIR=%{_unitdir}

%__make %{?_smp_mflags}

%install
%make_install

mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}
mkdir -p %{buildroot}%{_sysconfdir}/package-manager/server
mkdir -p %{buildroot}%{db_dir}
install -m 0600 restriction.db %{buildroot}%{db_dir}

%fdupes %{buildroot}

%post
/sbin/ldconfig

%files
%manifest %{name}.manifest
%defattr(-,root,root,-)
%{_unitdir}/package-manager.service
%{_datadir}/dbus-1/system-services/org.tizen.pkgmgr.service
%config %{_sysconfdir}/dbus-1/system.d/org.tizen.pkgmgr.conf
%config(noreplace) %{db_dir}
%config(noreplace) %{db_dir}/restriction.db
%{_bindir}/pkgmgr-server
%{_sysconfdir}/package-manager/server
/usr/share/license/%{name}
