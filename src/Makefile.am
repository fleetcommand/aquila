# for gettext
PACKAGE = @PACKAGE@
VERSION = @VERSION@

top_srcdir = @top_srcdir@
subdir = src

#
## NLS Support
#
datadir = @datadir@
localedir = $(datadir)/locale
LOCALE_DEFS=-DLOCALEDIR=\"$(localedir)\"
# "

#
## Set the correct flags for debugging support
#
if DEBUG
DEBUG_CFLAGS = -DDEBUG
DEBUG_FILES = stacktrace.c
else
DEBUG_CFLAGS =
DEBUG_FILES =
endif

#
## set platform specific stuff.
#
if USE_WINDOWS
WINDOWS_DEFS = -DUSE_WINDOWS
WINDOWS_OBJS = aquila.res
else
if GETADDRINFO
GETADDRINFO_SOURCES = getaddrinfo.c
endif
if USE_PTHREADDNS
DNS_FILES = dns.c
DNS_FLAGS = -D_REENTRANT -DUSE_PTHREADDNS
endif
endif

#
## Add plugins
#

if PLUGIN_CHATLOG
CHATLOG_SOURCES = pi_chatlog.c
endif
if PLUGIN_CHATROOM
CHATROOM_SOURCES = pi_chatroom.c
endif 
if PLUGIN_CONFIGLOCK
CONFIGLOCK_SOURCES =  pi_configlock.c
endif
if PLUGIN_HUBLIST
HUBLIST_SOURCES =  pi_hublist.c
endif
if PLUGIN_IPLOG
IPLOG_SOURCES =  pi_iplog.c
endif
if PLUGIN_LUA
LUA_SOURCES = pi_lua.c
LUA_LIBS = 
endif
if PLUGIN_STATBOT
STATBOT_SOURCES =  pi_statbot.c
endif
if PLUGIN_RRD
RRD_SOURCES =  pi_rrd.c
endif
if PLUGIN_RSS
RSS_SOURCES =  pi_rss.c
endif
if PLUGIN_STATISTICS
STATISTICS_SOURCES =  pi_statistics.c
endif
if PLUGIN_TRIGGER
TRIGGER_SOURCES =  pi_trigger.c
endif
if PLUGIN_USER
USER_SOURCES =  pi_user.c banlistclient.c
endif

PLUGIN_SOURCES= $(CHATLOG_SOURCES) \
		$(CHATROOM_SOURCES) \
		$(CONFIGLOCK_SOURCES) \
		$(HUBLIST_SOURCES) \
		$(IPLOG_SOURCES) \
		$(LUA_SOURCES) \
		$(RRD_SOURCES) \
		$(RSS_SOURCES) \
		$(STATBOT_SOURCES) \
		$(STATISTICS_SOURCES) \
		$(TRIGGER_SOURCES) \
		$(USER_SOURCES)

PLUGIN_CFLAGS = @PLUGIN_CHATLOG@ \
		@PLUGIN_CHATROOM@ \
		@PLUGIN_CONFIGLOCK@ \
		@PLUGIN_HUBLIST@ \
		@PLUGIN_IPLOG@ \
		@PLUGIN_LUA@ @LUA_INCLUDES@ \
		@PLUGIN_RRD@ @RRD_INCLUDES@ \
		@PLUGIN_RSS@ \
		@PLUGIN_STATBOT@ \
		@PLUGIN_STATISTICS@ \
		@PLUGIN_TRIGGER@ \
		@PLUGIN_USER@

PLUGIN_LIBS = @LUALIB@ @RRD_LIBS@

if EPOLL
NETWORKAPI_CFLAGS = -DUSE_EPOLL
NETWORKAPI_FILES  = esocket_epoll.c
endif
if POLL
NETWORKAPI_CFLAGS = -DUSE_POLL
NETWORKAPI_FILES  = esocket_poll.c
endif
if SELECT
NETWORKAPI_CFLAGS = -DUSE_SELECT
NETWORKAPI_FILES  = esocket_select.c
endif
if IOCP
NETWORKAPI_CFLAGS = -DUSE_IOCP
NETWORKAPI_FILES  = esocket_iocp.c
endif
		
# end plugins

DEFS = @DEFS@ $(LOCALE_DEFS) $(WINDOWS_DEFS)

AM_CFLAGS=$(DEBUG_CFLAGS) $(NETWORKAPI_CFLAGS) @ZLINE@ @GEOIP@ @GEOIP_INCLUDES@ @GCC_CFLAGS@ @ALLOW_EPOLL@ @ALLOW_POLL@ @ALLOW_IOCP@ @CYGWIN_CFLAGS@ $(DNS_FLAGS) $(PLUGIN_CFLAGS)

EXTRA_DIST = buffer.h commands.h hash.h nmdc_protocol.h rbt.h banlistclient.h config.h hashlist.h \
	     nmdc_token.h stringlist.h core_config.h hashlist_func.h nmdc_utils.h user.h buffer.h \
	     defaults.h hub.h plugin.h utils.h builtincmd.h dllist.h leakybucket.h plugin_int.h cap.h \
	     esocket.h nmdc.h proto.h stacktrace.c stacktrace.h getaddrinfo.h getaddrinfo.c pi_lua.c \
	     nmdc_nicklistcache.h banlist.h nmdc_local.h tth.h aqtime.h iplist.h gettext.h dns.h xml.h \
	     sys_windows.h flags.h aquila.rc etimer.h value.h stats.h \
	     esocket_epoll.c esocket_poll.c esocket_select.c esocket_iocp.c

DISTCLEANFILES = .indent
STACKTRACEFILES = stacktrace.c

NMDC_SOURCES = nmdc_token.c nmdc_protocol.c nmdc_nicklistcache.c nmdc_utils.c nmdc.c nmdc_interface.c

NETWORK_SOURCES = $(NETWORKAPI_FILES) etimer.c buffer.c rbt.c

bin_PROGRAMS = aquila
aquila_SOURCES = $(NETWORK_SOURCES) \
		 stringlist.c \
		 utils.c \
		 hash.c \
		 dllist.c \
		 leakybucket.c \
		 config.c \
		 hub.c \
		 core_config.c \
		 hashlist.c \
		 user.c \
		 banlist.c \
		 plugin.c \
		 commands.c \
		 builtincmd.c \
		 flags.c \
		 cap.c \
		 main.c \
		 tth.c \
		 aqtime.c \
		 iplist.c \
		 xml.c \
		 value.c \
		 stats.c \
		 $(NMDC_SOURCES) \
		 $(PLUGIN_SOURCES) \
		 $(DEBUG_FILES) \
		 $(GETADDRINFO_SOURCES) \
		 $(DNS_FILES)

aquila_LDADD = @GEOIP_LIBS@ @ZLIB@ @CYGWIN_LDFLAGS@ @LIBINTL@ $(PLUGIN_LIBS) $(WINDOWS_OBJS)

indent: .indent

.indent: $(aquila_SOURCES)
	indent -l100 -bad -bap -br -ce -cli2 -cbi2 -nss -nbc -brs -lp -npsl -saf -sai -saw $?
	rm *~
	touch .indent

commit:
	make -C .. commit

%.gcno: %.c
	touch $@

%.gcda: %.c
	touch $@

%.c.gcov : %.c %.gcno %.gcda
	gcov $(*).c || touch $(*).c.gcov

coverage: $(aquila_SOURCES:.c=.c.gcov)
	-cat $^ > coverage

coverage2: $(aquila_SOURCES)
	gcov -bn $^ > coverage2

clean-local:
	-rm -f *.gcov *.gcno *.gcda

aquila.res: aquila.rc ../contrib/aquila.ico
	windres $(DEFS) aquila.rc -I ../contrib -O coff -o aquila.res
