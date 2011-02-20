/*                                                                                                                                    
 *  (C) Copyright 2006 Johan Verrept (jove@users.berlios.de)                                                                      
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *  
 */

#include "hub.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifndef ENABLE_NLS
#include <locale.h>
#endif
#ifndef USE_WINDOWS
#include <sys/wait.h>
#endif

#include "defaults.h"
#include "gettext.h"
#include "aqtime.h"
#include "proto.h"
#include "config.h"
#include "stats.h"
#include "user.h"
#include "plugin_int.h"
#include "builtincmd.h"
#include "commands.h"
#include "etimer.h"

#include "nmdc.h"

/* FIXME: for nmdc_proto.cache_flush */
#include "nmdc_protocol.h"

#ifdef DEBUG
#include "stacktrace.h"
#endif

#ifdef USE_WINDOWS
#include "sys_windows.h"
#endif

/* global data */

struct timeval boottime;

typedef struct {
  /* go to daemon mode */
  unsigned int detach;
  unsigned int restart;

  /* seperate working dir */
  unsigned int setwd;
  unsigned char *wd;

  /* pid/lock file */
  unsigned int setlock;
  unsigned char *lock;
} args_t;

args_t args = {
detach:0,
restart:0,

setwd:0,
wd:NULL,

setlock:0,
lock:"aquila.pid"
};

/* utility functions */

void usage (unsigned char *name)
{
  printf ("Usage: %s [-hd] [-p <pidfile>] [-c <config dir>]\n"
	  "  -h : print this help\n"
	  "  -v : print version\n"
	  "  -d : detach (run as daemon)\n"
	  "  -r : automatically restart hub if it shuts down\n"
	  "  -p : specify pidfile\n" "  -c : specify config directory\n", name);
}

void version ()
{
  printf (HUBSOFT_NAME " " VERSION "\n");
}

void parseargs (int argc, char **argv)
{
  int opt;

  while ((opt = getopt (argc, argv, "hvdrp:c:")) > 0) {
    switch (opt) {
      case '?':
      case 'h':
	usage (argv[0]);
	exit (0);
      case 'v':
	version ();
	exit (0);
	break;
      case 'd':
	args.detach = 1;
	break;
      case 'r':
	args.restart = 1;
	break;
      case 'p':
	if (args.setlock)
	  free (args.lock);
	args.setlock = 1;
	args.lock = strdup (optarg);
	break;
      case 'c':
	if (args.setwd)
	  free (args.wd);
	args.setwd = 1;
	args.wd = strdup (optarg);
	break;
    }
  }
}

void daemonize (char **argv)
{
#ifndef USE_WINDOWS
  int i, lockfd;
  unsigned char pid[16];

  /* detach if asked */
  if (args.detach) {
    if (getppid () == 1)
      return;			/* already a daemon */

    /* fork to guarantee we are not process group leader */
    i = fork ();
    if (i < 0)
      exit (1);			/* fork error */
    if (i > 0)
      exit (0);			/* parent exits */

    /* child (daemon) continues */
    setsid ();			/* obtain a new process group */

    /* fork again so we become process group leader 
     *  and cannot regain a controlling tty 
     */
    i = fork ();
    if (i < 0)
      exit (1);			/* fork error */
    if (i > 0)
      exit (0);			/* parent exits */

    /* close all fds */
    for (i = getdtablesize (); i >= 0; --i)
      close (i);		/* close all descriptors */

    /* close parent fds and send output to fds 0, 1 and 2 to bitbucket */
    i = open ("/dev/null", O_RDWR);
    if (i < 0)
      exit (1);
    dup (i);
    dup (i);			/* handle standard I/O */
  }

  /* change to working directory */
  if (args.setwd)
    chdir (args.wd);

  /* create local lock */
  lockfd = open (args.lock, O_RDWR | O_CREAT, 0640);
  if (lockfd < 0) {
    perror ("lock: open");
    exit (1);
  }
#ifndef __CYGWIN__
  /* lock the file */
  if (lockf (lockfd, F_TLOCK, 0) < 0) {
    perror ("lock: lockf");
    printf (HUBSOFT_NAME " is already running.\n");
    exit (0);
  }
#else
  /* lock the file */
  {
    struct flock lock;

    lock.l_type = F_RDLCK;
    lock.l_start = 0;
    lock.l_whence = SEEK_SET;
    lock.l_len = 0;

    if (fcntl (lockfd, F_SETLK, &lock) < 0) {
      perror ("lock: lockf");
      printf (HUBSOFT_NAME " is already running.\n");
      exit (0);
    }
  }
#endif
  /* write to pid to lockfile */
  snprintf (pid, 16, "%d\n", getpid ());
  write (lockfd, pid, strlen (pid));

  /* restrict created files to 0750 */
  umask (027);

  /* Auto restart code.
   * fork to start the hub and fork again if the child exits
   */
  if (args.restart) {
    time_t stamp, tnow;
    sigset_t set, oldset;
    struct stat bstat, nstat;

    stat (*argv[0] ? argv[0] : "/proc/self/exe", &bstat);

    /* block all signals except SIG_CHILD */
    sigemptyset (&set);
    sigaddset (&set, SIGCHLD);
    sigprocmask (SIG_SETMASK, &set, &oldset);

    time (&tnow);
    do {
      /* record fork time */
      stamp = tnow;

      /* fork the child */
      i = fork ();

      if (i < 0)
	exit (1);		/* fork error */

      /* the child exists the loop to start the actual hub */
      if (i == 0)
	break;

      /* we wait until the child exits */
      wait (NULL);

      /* guard against fork storms */
      time (&tnow);
      if ((tnow - stamp) < MIN_FORK_RETRY_PERIOD)
	sleep (MIN_FORK_RETRY_PERIOD - (tnow - stamp));

      /* first we check if the executable has changed, if so, we
       *  start the new executable instead of forking
       */
      stat (*argv[0] ? argv[0] : "/proc/self/exe", &nstat);
      if (nstat.st_mtime != bstat.st_mtime)
	execvp (*argv[0] ? argv[0] : "/proc/self/exe", argv);

      /* loop to restart child */
    } while (1);

    /* restore childs signal mask */
    sigprocmask (SIG_SETMASK, &oldset, NULL);
  }
#endif
}

/*
 * MAIN LOOP
 */
int main (int argc, char **argv)
{
  int ret, cont;
  struct timeval to, tnow, tnext;
  esocket_handler_t *h;

#ifndef USE_WINDOWS
  sigset_t set;


  /* block SIGPIPE */
  sigemptyset (&set);
  sigaddset (&set, SIGPIPE);
  sigaddset (&set, SIGURG);
  sigprocmask (SIG_BLOCK, &set, NULL);
#endif

  /* unbuffer the output */
  setvbuf (stdout, (char *) NULL, _IOLBF, 0);

#if ENABLE_NLS
  /* we adjust the language to the enviroment, but
     the decimal point is hardcoded to .
   */
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);
  setlocale (LC_ALL, "");
  setlocale (LC_NUMERIC, "C");
#endif

#ifdef DEBUG
  /* add stacktrace handler */
  StackTraceInit (argv[0], -1);
#endif

#ifdef __USE_W32_SOCKETS
  {
    WSADATA wsd;

    ret = WSAStartup (MAKEWORD (2, 0), &wsd);
    if (ret) {
      return 0;
    }
  }
#endif

  /* parse arguments */
  parseargs (argc, argv);

  /* deamonize */
  daemonize (argv);

  /* initialize the global configuration */
  gettime ();
  etimer_start ();
  config_init ();
  stats_init ();
  accounts_init ();
  plugin_init ();
  command_init ();
  builtincmd_init ();
  server_init ();
  nmdc_init ();

  /* register boottime stat */
  stats_register ("boottime", VAL_ELEM_ULONG, &boottime.tv_sec, "Hub boottime in unix time.");

  /* initialize the plugins */
#ifdef PLUGIN_IPLOG
  pi_iplog_init ();
#endif
#ifdef PLUGIN_USER
  pi_user_init ();
#endif
#ifdef PLUGIN_CHATROOM
  pi_chatroom_init ();
#endif
#ifdef PLUGIN_STATISTICS
  pi_statistics_init ();
#endif
#ifdef PLUGIN_TRIGGER
  pi_trigger_init ();
#endif
#ifdef PLUGIN_CHATLOG
  pi_chatlog_init ();
#endif
#ifdef PLUGIN_STATBOT
  pi_statbot_init ();
#endif
#ifdef PLUGIN_HUBLIST
  pi_hublist_init ();
#endif
#ifdef PLUGIN_CONFIGLOCK
  pi_configlock_init ();
#endif
#ifdef PLUGIN_RSS
  pi_rss_init ();
#endif
#ifdef PLUGIN_RRD
  pi_rrd_init (h);
#endif

  plugin_config_load (NULL);

  /* add lowest member of the statistics */
  gettimeofday (&boottime, NULL);

  /* initialize the random generator */
  srandom (boottime.tv_sec ^ boottime.tv_usec);

  /* setup socket handler */
  h = esocket_create_handler (5);

  /* setup server */
  server_setup (h);
  nmdc_setup (h);
  command_setup ();

#ifdef PLUGIN_HUBLIST
  pi_hublist_setup (h);
#endif
#ifdef PLUGIN_RSS
  pi_rss_setup (h);
#endif

#ifdef PLUGIN_LUA
#ifdef HAVE_LUA_H
  /* lua must only be loaded last. */
  pi_lua_init ();
#endif
#endif

  /* main loop */
  gettimeofday (&tnext, NULL);
  tnext.tv_sec += 1;
  cont = 1;
  for (; cont;) {
    /* do not assume select does not alter timeout value */
    to.tv_sec = 0;
    to.tv_usec = 100000;

    /* wait until an event */
    ret = esocket_select (h, &to);

    /* 1s periodic cache flush */
    gettimeofday (&tnow, NULL);
    if (timercmp (&tnow, &tnext, >=)) {
      while (timercmp (&tnow, &tnext, >=))
	tnext.tv_sec += 1;
      now = tnow;
      nmdc_proto.flush_cache ();
    }
  }
  /* should never be reached... */
  printf ("Shutdown\n");

  return 0;
}
