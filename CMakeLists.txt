CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
SET(CMAKE_ALLOW_LOOSE_LOOP_CONSTRUCTS true)
SET(CMAKE_SKIP_BUILD_RPATH true)

PROJECT(pkgmgr-server C)
SET(VERSION_MAJOR 0)
SET(VERSION ${VERSION_MAJOR}.1.68)

SET(PREFIX ${CMAKE_INSTALL_PREFIX})
SET(EXEC_PREFIX "\${prefix}")
SET(LIBDIR ${LIB_INSTALL_DIR})
SET(INCLUDEDIR "\${prefix}/include")

ADD_DEFINITIONS(-DDB_DIR="${DB_DIR}")
ADD_DEFINITIONS(-DRUN_DIR="${RUN_DIR}")
ADD_DEFINITIONS(-DBACKEND_DIR="${BACKEND_DIR}")

## Compiler flags
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden -g -Wall -fPIE")

## Linker flags
SET(CMAKE_EXE_LINKER_FLAGS "-Wl,--as-needed -pie")

INCLUDE_DIRECTORIES(include)
INCLUDE(FindPkgConfig)

SET(PKGMGR_SERVER "pkgmgr-server")
SET(SRCS
	src/pkgmgr-server.c
	src/request.c
	src/pm-queue.c
	src/restriction_mode.c
	)

pkg_check_modules(SERVER_DEPS REQUIRED
		gio-2.0
		dlog
		pkgmgr-parser
		pkgmgr-info
		libtzplatform-config
		drm-service-core-tizen
		libgum
		sqlite3
		pkgmgr
		pkgmgr-installer)
FOREACH(SERVER_FLAGS ${SERVER_DEPS_CFLAGS})
       SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${SERVER_FLAGS}")
ENDFOREACH(SERVER_FLAGS)

ADD_EXECUTABLE(${PKGMGR_SERVER} ${SRCS})
TARGET_LINK_LIBRARIES(${PKGMGR_SERVER} pkgmgr_installer)
TARGET_LINK_LIBRARIES(${PKGMGR_SERVER} ${SERVER_DEPS_LDFLAGS})

CONFIGURE_FILE(org.tizen.pkgmgr.service.in org.tizen.pkgmgr.service @ONLY)
CONFIGURE_FILE(org.tizen.pkgmgr.conf.in org.tizen.pkgmgr.conf @ONLY)
CONFIGURE_FILE(package-manager.service.in package-manager.service @ONLY)

INSTALL(TARGETS ${PKGMGR_SERVER} DESTINATION bin)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/org.tizen.pkgmgr.service DESTINATION ${PREFIX}/share/dbus-1/system-services/)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/org.tizen.pkgmgr.conf DESTINATION ${SYSCONF_INSTALL_DIR}/dbus-1/system.d/)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/package-manager.service DESTINATION ${UNITDIR})
