/**********************************************************************
 * daemon.c                                              September 1999
 * Horms                                             horms@vergenet.net
 *
 * Close and fork to become a daemon.
 *
 * Notes from unix programmer faq
 * http://www.landfield.com/faqs/unix-faq/programmer/faq/
 *
 * Almost none of this is necessary (or advisable) if your daemon is being
 * started by `inetd'.  In that case, stdin, stdout and stderr are all set up
 * for you to refer to the network connection, and the `fork()'s and session
 * manipulation should *not* be done (to avoid confusing `inetd').  Only the
 * `chdir()' and `umask()' steps remain as useful.
 * 
 * perdition
 * Mail retreival proxy server
 * Copyright (C) 1999  Horms
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 * 02111-1307  USA
 *
 **********************************************************************/

#include "daemon.h"
#include "options.h"


/**********************************************************************
 * daemon_process
 * Close and fork to become a daemon.
 * Note: daemon_inetd_process should be called if the process is being
 * run from inetd.
 **********************************************************************/

void daemon_process(void){
  /*
   * `fork()' so the parent can exit, this returns control to the command
   * line or shell invoking your program.  This step is required so that
   * the new process is guaranteed not to be a process group leader. The
   * next step, `setsid()', fails if you're a process group leader.
   * daemon_become_child();
   */
  daemon_become_child();

  /*
   * setsid()' to become a process group and session group leader. Since a
   * controlling terminal is associated with a session, and this new
   * session has not yet acquired a controlling terminal our process now
   * has no controlling terminal, which is a Good Thing for daemons.
   */
  if(setsid()<0){
    PERDITION_LOG(LOG_DEBUG, "daemon_process: setsid: %s", strerror(errno));
    PERDITION_LOG(LOG_ERR, "Fatal error begoming group leader. Exiting.\n");
    daemon_exit_cleanly(-1);
  }

  /*
   * fork()' again so the parent, (the session group leader), can exit.
   * This means that we, as a non-session group leader, can never regain a
   * controlling terminal.
   */
  daemon_become_child();

  /* chdir() and umask() */
  daemon_inetd_process();

  /*
   * `close()' fds 0, 1, and 2. This releases the standard in, out, and
   * error we inherited from our parent process. We have no way of knowing
   * where these fds might have been redirected to. Note that many daemons
   * use `sysconf()' to determine the limit `_SC_OPEN_MAX'.  `_SC_OPEN_MAX'
   * tells you the maximun open files/process. Then in a loop, the daemon
   * can close all possible file descriptors. You have to decide if you
   * need to do this or not.  If you think that there might be
   * file-descriptors open you should close them, since there's a limit on
   * number of concurrent file descriptors.
   */
   daemon_close_fd();

  /* Establish new open descriptors for stdin, stdout and stderr. Even if
   * you don't plan to use them, it is still a good idea to have them open.
   * The precise handling of these is a matter of taste; if you have a
   * logfile, for example, you might wish to open it as stdout or stderr,
   * and open `/dev/null' as stdin; alternatively, you could open
   * `/dev/console' as stderr and/or stdout, and `/dev/null' as stdin, or
   * any other combination that makes sense for your particular daemon.
   */
   if(open("/dev/null", O_RDONLY)<0){
     PERDITION_LOG(LOG_DEBUG, "daemon_process: open: %s", strerror(errno));
     PERDITION_LOG(LOG_ERR, "Fatal error Opening /dev/null. Exiting.");
     daemon_exit_cleanly(-1);
   }
   if(open("/dev/null", O_WRONLY|O_APPEND)<0){
     PERDITION_LOG(LOG_DEBUG, "daemon_process: open: %s" , strerror(errno));
     PERDITION_LOG(LOG_ERR, "Fatal error Opening /dev/null. Exiting.");
     daemon_exit_cleanly(-1);
   }
   if(open("/dev/null", O_WRONLY|O_APPEND)<0){
     PERDITION_LOG(LOG_DEBUG, "daemon_process: open: %s", strerror(errno));
     PERDITION_LOG(LOG_ERR, "Fatal error Opening /dev/null. Exiting.");
     daemon_exit_cleanly(-1);
   }
}


/**********************************************************************
 * daemon_inetd_process
 * Chdir to and umask
 * This is all we really need to do if our process is run from
 * inetd
 **********************************************************************/

void daemon_inetd_process(void){
  /*
   * `chdir("/")' to ensure that our process doesn't keep any directory in
   * use. Failure to do this could make it so that an administrator
   * couldn't unmount a filesystem, because it was our current directory.
   */
  if(chdir("/")<0){
    PERDITION_LOG(LOG_DEBUG, "daemon: chdir: %s", strerror(errno));
    PERDITION_LOG(LOG_ERR, "Fatal error changing directory to /. Exiting.");
    daemon_exit_cleanly(-1);
  }

  /*
   * `umask(0)' so that we have complete control over the permissions of
   * anything we write. We don't know what umask we may have inherited.
   */
  umask(0);
}


/**********************************************************************
 * daemon_become_child
 * Fork and exit from parent process. When we return 
 * we are our own clild. Very incestuous.
 **********************************************************************/

void daemon_become_child(void){
  int status;

  status=fork();

  if(status<0){
    PERDITION_LOG(LOG_DEBUG, "daemon_become_child: fork: %s", strerror(errno));
    PERDITION_LOG(LOG_ERR, "Fatal error forking. Exiting.");
    daemon_exit_cleanly(-1);
  }
  if(status>0){
    daemon_exit_cleanly(0);
  }
}


/**********************************************************************
 * daemon_close_fd
 * Close all the file descriptots a process has
 **********************************************************************/

void daemon_close_fd(void){
  int fd;
  long max_fd;

  fflush(NULL);

  if((max_fd=sysconf(_SC_OPEN_MAX))<2){
    PERDITION_LOG(LOG_DEBUG, "daemon_close_fd: sysconf: %s", strerror(errno));
    PERDITION_LOG(
      LOG_ERR, 
      "Fatal error finding maximum file descriptors. Exiting."
    );

    /*
     * don't use daemon_exit_cleanly as daemon_close_fd 
     * is called from daemon_exit_cleanly
     */
    exit(-1);
  }

  for(fd=0;fd<(int)max_fd;fd++){
    close(fd);
  }
}


/**********************************************************************
 * daemon_setid
 * Set the userid and groupid of the process.
 * Arguments are the username or the userid as a string and 
 * the group or the groupid as a string.
 **********************************************************************/

int daemon_setid(const char *user, const char *group){
  uid_t uid;
  gid_t gid;
  struct passwd *pw;
  struct group *gr;

  if(vanessa_socket_str_is_digit(group)){
    gid=(gid_t)atoi(group);
  }
  else{
    if((gr=getgrnam(group))==NULL){
      PERDITION_LOG(LOG_DEBUG, "daemon_setid: getgrnam: %s", strerror(errno));
      return(-1);
    }
    gid=gr->gr_gid;
    /*free(gr);*/
  }

  if(setgid(gid)){
    PERDITION_LOG(LOG_DEBUG, "daemon_setid: setgid: %s", strerror(errno));
    return(-1);
  }

  if(vanessa_socket_str_is_digit(user)){
    uid=(uid_t)atoi(user);
  }
  else{
    if((pw=getpwnam(user))==NULL){
      PERDITION_LOG(LOG_DEBUG, "daemon_setid: getpwnam: %s", strerror(errno));
      return(-1);
    }
    uid=pw->pw_uid;
    /*free(pw);*/
  }

  if(setuid(uid)){
    PERDITION_LOG(LOG_DEBUG, "daemon_setid: setuid: %s", strerror(errno));
    return(-1);
  }

  PERDITION_LOG(
    LOG_DEBUG, 
    "daemon_setid: uid=%d euid=%d gid=%d egid=%d",
    getuid(),
    geteuid(),
    getgid(),
    getegid()
  );

  return(0);
}



/**********************************************************************
 * daemon_exit_cleanly
 * If we get a sinal then close everthing, log it and quit
 **********************************************************************/

static int daemon_exit_cleanly_called=0;

void daemon_exit_cleanly(int i){
  if(daemon_exit_cleanly_called){ signal(i, SIG_DFL); abort(); }
  daemon_exit_cleanly_called=1;
  /*Only log if it is a signal, not a requested exit*/
  if(i>0){ PERDITION_LOG(LOG_INFO, "Exiting on signal %d", i); }
  daemon_close_fd();
  exit((i>0)?0:i);
}


/**********************************************************************
 * daemon_noop_handler
 * A signal handler that does nothing but reinstall itself
 * as the signal handler for the signal.
 * pre: sig: signal recieved by the process
 * post: signal handler reset for signal
 **********************************************************************/

void daemon_noop_handler(int sig){
  signal(sig, (void(*)(int))daemon_noop_handler);
}

