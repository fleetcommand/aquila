#                      -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT([[Aquila]], [[0.1.11-pre2-beta3]], [[jove@users.berlios.de]], [aquila])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/banlistclient.c])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_CPP
AM_PROG_CC_C_O
AC_CANONICAL_HOST

# check for gdb
AC_CHECK_TOOL([GDB], [gdb], [gdb])
AC_CHECK_TOOL([GPROF], [gprof], [gprof])
AC_CHECK_TOOL([STRIP],[strip])


AM_GNU_GETTEXT([external], [need-ngettext])
AM_CONDITIONAL(ENABLE_NLS, test "${USE_NLS}" = "yes")

# initialize local variables
sCFLAGS=

#
## Building for windows or for posix?
#
case "${host}" in
  *-*-cygwin)
  	buildtarget="win32"
  	;;
  *)
  	buildtarget="posix"
esac

#
## if we are building for windows, select mingw compiler.
#
if test ${buildtarget} = "win32"
then
	CFLAGS="${CFLAGS} -mno-cygwin"
	CPPFLAGS="${CPPFLAGS} -mno-cygwin"
	LDFLAGS="-Lsrc/lib -Llib ${LDFLAGS}"
fi

#
## GCC configuration. 
#
#  We set all warnings on, except some useless stuff. Set according to gcc version.
#
if test "${GCC}" = "yes" ;
then
	GCC_VERSION=`gcc --version | head -n 1 | cut -d ' ' -f 3`
	case $GCC_VERSION in
	3.3.*)  GCC_CFLAGS="-Wall -W -Wno-unused-parameter" ;;
	3.4.*)	GCC_CFLAGS="-Wall -Wextra -Wno-unused-parameter" ;;
	4.*.*)	GCC_CFLAGS="-Wall -Wextra -Wno-pointer-sign -Wno-unused-parameter" ;;
	esac
fi
AC_SUBST(GCC_CFLAGS)

##################################################################################################
#
#
#                                     CONFIGURE OPTIONS
#
#
##################################################################################################

#
## The debug argument. Enables lots of debug output in the program and causes all optimization to be disabled.
#
AC_ARG_ENABLE(debug,
	AC_HELP_STRING([--enable-debug],[Turn on debugging (default OFF)]),
	[case "$enableval" in
	  yes|true) debug=true
		 ;;
	  no|false) debug=false
	  	 ;;
	  *)   AC_MSG_ERROR(bad value ${enableval} for --enable-debug);;
	esac],
	[unset debug])
AM_CONDITIONAL(DEBUG, test x$debug = xtrue)

if test x$debug = xtrue;
then
	# always disable optimization and max debug output.
	sCFLAGS="${sCFLAGS} -g${GDB} -O0"
	
	# if we have gdb, enable coredumping
	if test x$GDB = xgdb
	then
		sCFLAGS="${sCFLAGS} -DDUMP_CORE"
	fi
fi;

#######################################
#
#          COMPILING OPTIONS
#
#######################################

#
## profiler arguent. This enables profiler options for the compiler.
#
AC_ARG_ENABLE(profiler,
	AC_HELP_STRING([--enable-profiler],[Turn on profiling (default OFF)]),
	[case "$enableval" in
	  yes|true) 
	  	if test "${GPROF}" = "gprof"
	  	then
		  	sCFLAGS="${sCFLAGS} -pg"
		else
			sCFLAGS="${sCFLAGS} -p"
		fi
		profiler=true;
		 ;;
	  no|false) 
	  	profiler=false;
	  	 ;;
	  *)   AC_MSG_ERROR(bad value ${enableval} for --enable-profiler);;
	esac],
	[])

#
## testcoverage. Allows determining of program testcoverage and is first stage for the useprofile option below.
#
AC_ARG_ENABLE(testcoverage,
	AC_HELP_STRING([--enable-testcoverage],[Turn on test coverage logging (default OFF)]),
	[case "$enableval" in
	  yes|true) 
	  	sCFLAGS="${sCFLAGS} -ggdb -O0 -fprofile-generate -ftest-coverage"
	  	testcoverage=true;
	  	 ;;
	  no|false)
		testcoverage=false; 
	  	 ;;
	  *)   AC_MSG_ERROR(bad value ${enableval} for --enable-testcoverage);;
	esac],
	[])

#
## useprofile. previously generated profiles are used to optimize the hub.
#
AC_ARG_ENABLE(useprofile,
	AC_HELP_STRING([--enable-useprofile],[Turn on optimization based on run-time profiles. This requires a previous run with option --enable-profiler. See FAQ. (default OFF)]),
	[case "$enableval" in
	  yes|true) 
	  	sCFLAGS="${sCFLAGS} -fprofile-use"
	  	useprofile=true;
	  	 ;;
	  no|false) 
	  	useprofile=false;
	  	 ;;
	  *)   AC_MSG_ERROR(bad value ${enableval} for --enable-testcoverage);;
	esac],
	[])


#
## Set the selected options for all test code.
#
if test "${sCFLAGS}" != ""
then
	CFLAGS="${sCFLAGS}"
fi;
AC_SUBST(CFLAGS)

#######################################
#
#           HUB OPTIONS
#
#######################################

#
## pthreaddns arfument. Enables asynchronous resolving using a posix thread.
#
AC_ARG_ENABLE(pthreaddns,
	AC_HELP_STRING([--enable-pthreaddns],[Turn on posix threads DNS resolving (Default ON).]),
	[case "$enableval" in
	  yes|true) pthreaddns=true
		 ;;
	  no|false) pthreaddns=false
	  	 ;;
	  *)   AC_MSG_ERROR(bad value ${enableval} for --enable-pthreaddns);;
	esac],
	[pthreaddns=true])

#
## Add geoip argument
#
AC_ARG_ENABLE(geoip,
	AC_HELP_STRING([--enable-geoip],[Turn on GeoIP support (default ON)]),
	[case "$enableval" in
	  yes|true) GEOIP=-DGEOIP ;;
	  no|false) unset GEOIP ;;
	  *)   AC_MSG_ERROR(bad value ${enableval} for --enable-geoip);;
	esac],
	[GEOIP=-DGEOIP])
AC_SUBST(GEOIP)

#
## Add zline argument
#
AC_ARG_ENABLE(zline,
	AC_HELP_STRING([--enable-zline],[Turn on ZLine support (default ON)]),
	[case "$enableval" in
	  yes|true) ZLINE=-DZLINES ;;
	  no|false) unset ZLINE ;;
	  *)   AC_MSG_ERROR(bad value ${enableval} for --enable-zline);;
	esac],
	[ZLINE=-DZLINES])
AC_SUBST(ZLINE)

#
## Add epoll argument. This allows users to disable epoll usage. Mostly for 2.4 kernels or older glibcs
#
AC_ARG_ENABLE(epoll,
	AC_HELP_STRING([--enable-epoll],[Allow epoll (default ON).]),
	[case "$enableval" in
	  yes|true) ALLOW_EPOLL=-DALLOW_EPOLL ;;
	  no|false) unset ALLOW_EPOLL ;;
	  *)   AC_MSG_ERROR(bad value ${enableval} for --enable-epoll);;
	esac],
	[ALLOW_EPOLL=-DALLOW_EPOLL])

#
## Allow falback to poll. Poll is slow, but less limited than select.
#
AC_ARG_ENABLE(poll,
	AC_HELP_STRING([--enable-poll],[Allow poll() if no epoll (default ON).]),
	[case "$enableval" in
	  yes|true) ALLOW_POLL=-DALLOW_POLL ;;
	  no|false) unset ALLOW_POLL ;;
	  *)   AC_MSG_ERROR(bad value ${enableval} for --enable-poll);;
	esac],
	[ALLOW_POLL=-DALLOW_POLL])

#
## Allow IOCP. this is the prefered method for cygwin.
#
AC_ARG_ENABLE(iocp,
	AC_HELP_STRING([--enable-iocp],[Allow IO Ccompletion Ports, this is the preferred method on cygwin (default ON).]),
	[case "$enableval" in
	  yes|true) ALLOW_IOCP=-DALLOW_IOCP ;;
	  no|false) unset ALLOW_IOCP ;;
	  *)   AC_MSG_ERROR(bad value ${enableval} for --enable-iocp);;
	esac],
	[ALLOW_IOCP=-DALLOW_IOCP])

# disabled on any platform except win32
if test "${buildtarget}" = "win32"
then
	# verify is we can find all necessary headers
  	if test "${ALLOW_IOCP}" != ""
  	then
  		AC_CHECK_HEADERS([windows.h])
  		save_CFLAGS="$CFLAGS"
  		save_LDFLAGS="$LDFLAGS"
  		LDFLAGS="$LDFLAGS -lwsock32"
  		AC_MSG_CHECKING([for CreateIoCompletionPort])
  		AC_LINK_IFELSE(
  			[
  				AC_LANG_PROGRAM(
  					[[
  						#include <windows.h>
  					]],
  					[[
  						(void)CreateIoCompletionPort(0, 0, 0, 0);
  					]])
  			],
  			[
  				AC_MSG_RESULT([yes])
  				AC_DEFINE([HAVE_CREATEIOCOMPLETIONPORT], [1], [CreateIoCompletion port is defined and usable.])
  			 	CYGWIN_CFLAGS="$CYGWIN_CFLAGS -D__USE_W32_SOCKETS"
  			 	CYGWIN_LDFLAGS="$CYGWIN_LDFLAGS -lwsock32 -lws2_32"
  			 	ac_cv_func_createiocompletionport=yes
  			],
  			[
  				AC_MSG_RESULT([no]) 
  				unset ALLOW_IOCP
  			 	ac_cv_func_createiocompletionport=no
  			]
  		)
		CFLAGS="$save_CFLAGS"
		LDFLAGS="$save_LDFLAGS"
  	fi
  	if test x$debug != xtrue
  	then
  		CYGWIN_LDFLAGS="$CYGWIN_LDFLAGS -Wl,--subsystem,windows";
  	fi
else
  	unset ALLOW_IOCP
fi

AQ_PLUGIN_OPTION([PLUGIN_CHATLOG],	[chatlog],	[ON])
AQ_PLUGIN_OPTION([PLUGIN_CHATROOM],	[chatroom],	[ON])
AQ_PLUGIN_OPTION([PLUGIN_CONFIGLOCK],	[configlock],	[OFF])
AQ_PLUGIN_OPTION([PLUGIN_HUBLIST],	[hublist],	[ON])
AQ_PLUGIN_OPTION([PLUGIN_IPLOG],	[iplog],	[ON])
AQ_PLUGIN_OPTION([PLUGIN_RRD],		[rrd],		[OFF])
AQ_PLUGIN_OPTION([PLUGIN_RSS],		[rss],		[ON])
AQ_PLUGIN_OPTION([PLUGIN_STATBOT],	[statbot],	[ON])
AQ_PLUGIN_OPTION([PLUGIN_STATISTICS],	[statistics],	[ON])
AQ_PLUGIN_OPTION([PLUGIN_TRIGGER],	[trigger],	[ON])
AQ_PLUGIN_OPTION([PLUGIN_USER],		[user],		[ON])

#
## GEOIP Support
#
AC_ARG_WITH([geoip-prefix],
            [AS_HELP_STRING([--with-geoip-prefix=DIR],
                            [GeoIP files are in DIR])])
AC_ARG_WITH([geoip-includes],
            [AS_HELP_STRING([--with-geoip-includes=DIR],
                            [GeoIP include file is in DIR])])
AC_ARG_WITH([geoip-libraries],
            [AS_HELP_STRING([--with-geoip-libraries=DIR],
                            [GeoIP library file is in DIR])])


if test "x$with_geoip_prefix" = x; then
    geoip_search_path="$PATH"
else
    geoip_search_path="$with_geoip_prefix/bin"
fi

if test "x$with_geoip_includes" != x; then
    GEOIP_INCLUDES="-I$with_geoip_includes"
elif test "x$with_geoip_prefix" != x; then
    GEOIP_INCLUDES="-I$with_geoip_prefix/include"
fi

if test "x$with_geoip_libraries" != x; then
    GEOIP_LIBS="-L$with_geoip_libraries"
elif test "x$with_geoip_prefix" != x; then
    GEOIP_LIBS="-L$with_geoip_prefix/lib"
fi

#
## RRD Support
#
AC_ARG_WITH([rrd-prefix],
            [AS_HELP_STRING([--with-rrd-prefix=DIR],
                            [RRD files are in DIR])])
AC_ARG_WITH([rrd-includes],
            [AS_HELP_STRING([--with-rrd-includes=DIR],
                            [RRD include file is in DIR])])
AC_ARG_WITH([rrd-libraries],
            [AS_HELP_STRING([--with-rrd-libraries=DIR],
                            [RRD library file is in DIR])])


if test "x$with_rrd_prefix" = x; then
    rrd_search_path="$PATH"
else
    rrd_search_path="$with_rrd_prefix/bin"
fi

if test "x$with_rrd_includes" != x; then
    RRD_INCLUDES="-I$with_rrd_includes"
elif test "x$with_rrd_prefix" != x; then
    RRD_INCLUDES="-I$with_rrd_prefix/include"
fi

if test "x$with_rrd_libraries" != x; then
    RRD_LIBS="-L$with_rrd_libraries"
elif test "x$with_rrd_prefix" != x; then
    RRD_LIBS="-L$with_rrd_prefix/lib"
fi


#
## LUA Support
#
AQ_PLUGIN_OPTION([PLUGIN_LUA],		[lua],		[ON])

# some extra lua options
AC_ARG_WITH([lua-prefix],
            [AS_HELP_STRING([--with-lua-prefix=DIR],
                            [Lua files are in DIR])])
AC_ARG_WITH([lua-includes],
            [AS_HELP_STRING([--with-lua-includes=DIR],
                            [Lua include files are in DIR])])
AC_ARG_WITH([lua-libraries],
            [AS_HELP_STRING([--with-lua-libraries=DIR],
                            [Lua library files are in DIR])])
AC_ARG_WITH([lua-suffix],
            [AS_HELP_STRING([--with-lua-suffix=ARG],
                            [Lua binary and library files are suffixed with
                             ARG])])

if test "x$with_lua_prefix" = x; then
    lua_search_path="$PATH"
else
    lua_search_path="$with_lua_prefix/bin"
fi

if test "x$with_lua_includes" != x; then
    LUA_INCLUDES="-I$with_lua_includes"
elif test "x$with_lua_prefix" != x; then
    LUA_INCLUDES="-I$with_lua_prefix/include"
fi

if test "x$with_lua_libraries" != x; then
    LUA_LIBS="-L$with_lua_libraries"
elif test "x$with_lua_prefix" != x; then
    LUA_LIBS="-L$with_lua_prefix/lib"
fi

#
## define variables.
#
AC_SUBST(CYGWIN_LDFLAGS)
AC_SUBST(CYGWIN_CFLAGS)
AC_SUBST(ALLOW_IOCP)
AM_CONDITIONAL(USE_WINDOWS, test "$ALLOW_IOCP" != "")

##################################################################################################
#
#
#                                         LIBRARY CHECKS
#
#
##################################################################################################

#
## Crypt library for passwords
#
AC_CHECK_LIB(crypt, crypt)

#
## GeoIP library
#
if test "${GEOIP}" = "" ;
then
	unset GEOIP;
else
	save_LIBS="$LIBS"
	LIBS="$GEOIP_LIBS $LIBS"
	AC_CHECK_LIB([GeoIP], [GeoIP_id_by_ipnum], [GEOIP_LIBS="$GEOIP_LIBS -lGeoIP"], [unset GEOIP])
	LIBS="$save_LIBS"
fi

#
## ZLib library for ZLINE/ZPIPE support
#
if test "${ZLINE}" = "" ;
then
	unset ZLIB;
else
	AC_CHECK_LIB([z], [deflate], [ZLIB=-lz], [unset ZLINE])
fi
AC_SUBST(ZLIB)

if test "$buildtarget" != "win32"
then
	if test "$pthreaddns" = "true"
	then
		AC_CHECK_LIB([pthread], [pthread_create])
	fi
fi
AM_CONDITIONAL(USE_PTHREADDNS, test "$ac_cv_lib_pthread_pthread_create" = "yes")

if test "$PLUGIN_RRD" != ""
then
	# set the custom include paths
	save_LIBS="$LIBS"
	LIBS="$LIBS $RRD_LIBS"
	AC_CHECK_LIB([rrd], [rrd_create], [RRD_LIBS="$RRD_LIBS -lrrd"], [AQ_PLUGIN_DISABLE([PLUGIN_RRD], [rrd])])
	LIBS=$save_LIBS
fi
AC_SUBST(RRD_LIBS)

##################################################################################################
#
#
#                                         HEADER CHECKS
#
#
##################################################################################################
AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h inttypes.h stdint.h stdlib.h string.h strings.h sys/time.h unistd.h crypt.h string.h memory.h stdlib.h malloc.h])
AC_CHECK_HEADERS([arpa/inet.h netdb.h netinet/in.h netinet/tcp.h sys/socket.h locale.h])

# if epoll is enables, check for the header
if test "${ALLOW_EPOLL}" != "" ;
then
	AC_CHECK_HEADERS([sys/epoll.h])
fi

# if epoll is enables, check for the header
if test "${ALLOW_POLL}" != "" ;
then
	AC_CHECK_HEADERS([sys/poll.h])
fi

#
##   GeoIP
#
if test "${GEOIP}" != "";
then
	save_CPPFLAGS="$CPPFLAGS"
	CPPFLAGS="$GEOIP_INCLUDES $CPPFLAGS"
	AC_CHECK_HEADERS([GeoIP.h])
	CPPFLAGS="$safe_CPPFLAGS"
fi

if test x$GEOIP = x
then
	unset GEOIP_INCLUDES
	unset GEOIP_LIBS
fi
AC_SUBST(GEOIP_INCLUDES)
AC_SUBST(GEOIP_LIBS)


#
## ZLine
#
if test "${ZLINE}" != "";
then
	AC_CHECK_HEADERS([zlib.h], [], [unset ZLINE])
fi


#
## RRD
#
if test "${PLUGIN_RRD}" != "";
then
	save_CPPFLAGS="$CPPFLAGS"
	CPPFLAGS="$CPPFLAGS $RRD_INCLUDES"
	AC_CHECK_HEADERS([rrd.h], [], [AQ_PLUGIN_DISABLE([PLUGIN_RRD], [rrd])])
	CPPFLAGS="$save_CPPFLAGS"
fi
AC_SUBST(RRD_INCLUDES)


#
## LUA
#
if test "${PLUGIN_LUA}" != "" ;
then
	# set the custom include paths
	save_CPPFLAGS="$CPPFLAGS"
	CPPFLAGS="$CPPFLAGS $LUA_INCLUDES"
	AC_CHECK_HEADERS([lua.h lualib.h])

	# now also set the custom lib paths
	save_LIBS="$LIBS"
	LIBS="$LIBS $LUA_LIBS"

	AC_CHECK_LIB([m], [exp], [lua_extra_libs="$lua_extra_libs -lm"], [])
	LIBS="$save_LIBS $LUA_LIBS $lua_extra_libs"
	AC_CHECK_LIB([dl], [dlopen], [lua_extra_libs="$lua_extra_libs -ldl"], [])
	LIBS="$save_LIBS $LUA_LIBS $lua_extra_libs"
	AC_CHECK_LIB([lua$with_lua_suffix], [luaL_checklstring], [lua_extra_libs="$lua_extra_libs" ], [lua_extra_libs="-llualib$with_lua_suffix $lua_extra_libs"])
	LIBS="$save_LIBS $LUA_LIBS $lua_extra_libs"
	AC_CHECK_LIB([lua$with_lua_suffix],
             [lua_call],
             [LUA_LIBS="$LUA_LIBS -llua$with_lua_suffix $lua_extra_libs"],
             [unset LUA_LIBS],
             [$LUA_LIBS $lua_extra_libs])

	# restore the vars.
	CPPFLAGS="$save_CPPFLAGS"
	LIBS="$save_LIBS"

	if test "$LUA_LIBS" != ""
	then
		# check for version 5.0.x
		AC_MSG_CHECKING([for liblua version 5.0.x])
		save_CPPFLAGS="$CPPFLAGS"
		save_LIBS="$LIBS"
		CPPFLAGS="$CPPFLAGS $LUA_INCLUDES"
		LIBS="$LUA_LIBS $LIBS"
		AC_RUN_IFELSE([AC_LANG_SOURCE([[

			#include <lua.h>
			#include <stdlib.h>
			#include <string.h>
			#include <stdio.h>

			int main()
			{
			    printf("(found %s)... ", LUA_VERSION);
			    if(strstr (LUA_VERSION, "5.0"))
			        exit(EXIT_SUCCESS);
			    exit(EXIT_FAILURE);
			}

			]])],
        	      [
        	      	AC_MSG_RESULT([yes])
        	      	eval "LUAVERSION=50"
        	      ],
	              [AC_MSG_RESULT([no])]
	              )
		CPPFLAGS="$save_CPPFLAGS"
		LIBS="$save_LIBS"

		# if not found, test for 5.1.x
		if test x$LUAVERSION = x
		then
			AC_MSG_CHECKING([for liblua version 5.1.x])
			save_CPPFLAGS="$CPPFLAGS"
			save_LIBS="$LIBS"
			CPPFLAGS="$CPPFLAGS $LUA_INCLUDES"
			LIBS="$LUA_LIBS $LIBS"
			AC_RUN_IFELSE([AC_LANG_SOURCE([[
	
				#include <lua.h>
				#include <stdlib.h>
				#include <string.h>
				#include <stdio.h>
	
				int main()
				{
				    printf("(found %s)... ", LUA_VERSION);
				    if(strstr (LUA_VERSION, "5.1"))
				        exit(EXIT_SUCCESS);
				    exit(EXIT_FAILURE);
				}
	
				]])],
        		      [
        		      	AC_MSG_RESULT([yes])
        	      		eval "LUAVERSION=51"
        	      	      ],
		              [AC_MSG_RESULT([no])]
		              )
			CPPFLAGS="$save_CPPFLAGS"
			LIBS="$save_LIBS"
		fi

		# no lua found...
		if test x$LUAVERSION = x
		then
			unset LUA_LIBS
		fi
	fi
fi

LUALIB=${LUA_LIBS}
AC_SUBST(LUALIB)
AC_SUBST(LUA_INCLUDES)
AM_CONDITIONAL(LUA, test "${LUALIB}" != "" )
AC_DEFINE_UNQUOTED(LUAVERSION,	$LUAVERSION,	[LUA version detected.])

if test "${LUALIB}" = ""
then
	AQ_PLUGIN_DISABLE([PLUGIN_LUA], [lua])
fi

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T
AC_HEADER_TIME

##################################################################################################
#
#
#                                         FUNCTION CHECKS
#
#
##################################################################################################

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_SELECT_ARGTYPES
AC_TYPE_SIGNAL
AC_FUNC_STAT
AC_CHECK_FUNCS([gettimeofday inet_ntoa memset select socket strcasecmp strchr strdup strerror strncasecmp strstr strtol memcpy strcasestr mallinfo])
AC_REPLACE_FUNCS(memset)

AC_TYPE_SOCKLEN_T
AC_DECL_H_ERRNO

#
## Check for local getaddrinfo functions
#
AC_CHECK_FUNCS([getaddrinfo getnameinfo])
if test "$ac_cv_func_getaddrinfo$ac_cv_func_getnameinfo" != yesyes ; then
	AC_LIBOBJ(getaddrinfo)
fi
AM_CONDITIONAL(GETADDRINFO, test "$ac_cv_func_getaddrinfo$ac_cv_func_getnameinfo" != yesyes)

#
## if epoll is enabled, check for the function
#
if test "${ALLOW_EPOLL}" != "" ;
then
	AC_CHECK_FUNCS([epoll_wait])
	if test "$ac_cv_func_epoll_wait" != yes ;
	then
		unset ALLOW_EPOLL
	else
		AC_MSG_CHECKING([if epoll_wait implemented])
		AC_RUN_IFELSE(
			[AC_LANG_PROGRAM([[#include <sys/epoll.h>
					   #include <errno.h>
					]],
				[[
					struct epoll_event event;
					int fd = epoll_create(1);
					int retval = epoll_wait (fd, &event, 1, 0);
					if (retval <0) {
						perror (errno);
						exit (errno);
					};
					exit (0);
				]])],
			[AC_MSG_RESULT([yes])],
			[AC_MSG_RESULT([no]) 
			 unset ALLOW_EPOLL]
		)
	fi	
	
fi

#
## if poll is enabled, check for the function
#
if test "${ALLOW_POLL}" != "" ;
then
	AC_CHECK_FUNCS([poll])
fi

#
## Do socket system selection
#
eval "ALLOW_SELECT=1"

if test x$ALLOW_EPOLL != x
then
	# we need:
	#   sys/epoll.h
	#   working epoll_wait
	#   linux/eventpoll.h
	if test x$ac_cv_header_sys_epoll_h$ac_cv_func_epoll_wait = xyesyes
	then
		eval "USE_EPOLL=1"
	else
		unset ALLOW_EPOLL
	fi
fi

if test x$USE_EPOLL = x
then
	if test x$ALLOW_POLL != x -a x$ac_cv_header_sys_poll_h$ac_cv_func_poll = xyesyes
	then
		eval "USE_POLL=1"
	else
		unset ALLOW_EPOLL
	fi
fi

if test x$USE_EPOLL$USE_POLL = x
then
	if test x$ac_cv_func_select = xyes
	then
		eval "USE_SELECT=1"
	fi
fi

if test "$buildtarget" = "win32"
then
	if test x$ALLOW_IOCP != x
	then
		if test x$ac_cv_header_windows_h$ac_cv_func_createiocompletionport = xyesyes
		then
			eval "USE_IOCP=1"
		else
			unset ALLOW_IOCP
		fi
	fi
	if test x$USE_IOCP = x
	then
		echo "ERROR: you are building for Windows but your system does not appear to support IOCP."
	fi
	# whatever we do, don't use these on Windows.
	unset ALLOW_POLL
	unset ALLOW_EPOLL
	unset ALLOW_SELECT
	unset USE_SELECT
	unset USE_POLL
	unset USE_EPOLL
else
	if test x$USE_EPOLL$USE_POLL$USE_SELECT = x
	then
		echo "ERROR: your system does not support any of the basic IO systems Aquila requires."
	fi
	unset ALLOW_IOCP
fi

AC_SUBST(ALLOW_EPOLL)
AC_SUBST(ALLOW_POLL)
AC_SUBST(ALLOW_IOCP)
AC_SUBST(ALLOW_SELECT)

AC_SUBST(USE_EPOLL)
AC_SUBST(USE_POLL)
AC_SUBST(USE_SELECT)
AC_SUBST(USE_IOCP)

AM_CONDITIONAL(EPOLL,  test x$USE_EPOLL  != x)
AM_CONDITIONAL(POLL,   test x$USE_POLL   != x)
AM_CONDITIONAL(SELECT, test x$USE_SELECT != x)
AM_CONDITIONAL(IOCP,   test x$USE_IOCP   != x)


##################################################################################################
#
#
#                                         GENERATE OUTPUT
#
#
##################################################################################################

#
## Windows specific version numbering.
#
aquilaversion_MAJOR=`echo $VERSION | cut -d. -f 1`
aquilaversion_MINOR=`echo $VERSION | cut -d. -f 2`
aquilaversion_REV=`echo $VERSION | cut -d. -f3 | cut -d- -f1`
aquilaversion_PRE=`echo $VERSION | cut -d- -f2 | cut -c 4-`
aquilaversion_BETA=`echo $VERSION | cut -d- -f3 | sed 's/beta//' | sed 's/alpha//'`
if test x$aquilaversion_PRE = x
then
	aquilaversion_PRE=0
fi
if test x$aquilaversion_BETA = x
then
	aquilaversion_BETA=0
fi

AC_DEFINE_UNQUOTED(AQVER_MAJOR,	$aquilaversion_MAJOR,	[Aquila major version])
AC_DEFINE_UNQUOTED(AQVER_MINOR,	$aquilaversion_MINOR,	[Aquila minor version])
AC_DEFINE_UNQUOTED(AQVER_REV,	$aquilaversion_REV,	[Aquila revision])
AC_DEFINE_UNQUOTED(AQVER_PRE,	$aquilaversion_PRE,	[Aquila prerelease])
AC_DEFINE_UNQUOTED(AQVER_BETA,	$aquilaversion_BETA, 	[Aquila beta version])
AC_DEFINE_UNQUOTED(AQVER_SUB,	[(AQVER_PRE * 1000 + AQVER_BETA)], [Aquila sub version, calculated from prerelease and beta version])

AC_CONFIG_FILES([Makefile po/Makefile.in
                 src/Makefile
                 tools/Makefile])

AC_OUTPUT

##################################################################################################
#
#
#                                         GENERATE REPORT
#
#
##################################################################################################

echo "-------------------------------------------------------------------------------"
echo "                            Aquila configuration"

echo    "   HOST                                             " $host

AQ_REPORT_SECTION([I/O options])
AQ_IOSYS_REPORT([EPOLL],  [EPOLL Support (Linux only)])
AQ_IOSYS_REPORT([POLL],   [POLL Support])
AQ_IOSYS_REPORT([SELECT], [SELECT Support])
AQ_IOSYS_REPORT([IOCP],   [IOCP Support (Windows/Cygwin only)])

AQ_REPORT_SECTION([Hub options])

AQ_OPTION_REPORT([x$GEOIP != x],[GeoIP Support])
AQ_OPTION_REPORT([x$ZLINE != x],[ZLine/ZPipe Support])
AQ_OPTION_REPORT([x$USE_NLS != xno],[NLS Support])
AQ_OPTION_REPORT([x$ac_cv_lib_pthread_pthread_create = xyes],[Posix Threads Async Resolver])

AQ_REPORT_SECTION([Plugins])

AQ_PLUGIN_REPORT([chatlog])
AQ_PLUGIN_REPORT([chatroom])
AQ_PLUGIN_REPORT([configlock])
AQ_PLUGIN_REPORT([hublist])
AQ_PLUGIN_REPORT([iplog])
AQ_PLUGIN_REPORT([lua])
AQ_PLUGIN_REPORT([rrd])
AQ_PLUGIN_REPORT([rss])
AQ_PLUGIN_REPORT([statbot])
AQ_PLUGIN_REPORT([statistics])
AQ_PLUGIN_REPORT([trigger])
AQ_PLUGIN_REPORT([user])

AQ_REPORT_SECTION([These should be disabled for a normal build])

AQ_OPTION_REPORT([x$debug = xtrue],[DEBUG Support])
AQ_OPTION_REPORT([x$profiler = xtrue],[Profiler Support])
AQ_OPTION_REPORT([x$testcoverage = xtrue],[Test Coverage])
AQ_OPTION_REPORT([x$useprofile = xtrue],[Compile with runtime profiler optimization])

echo "-------------------------------------------------------------------------------"
