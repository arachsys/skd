#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <libgen.h>
#include <locale.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SYSLOG_NAMES
#include <sys/syslog.h>

static char *progname = "skd", *version = VERSION;
static int bgfd = -1, children = 0, logpid = 0, droprootprivs = 0;

void error(int status, int errnum, char *format, ...) {
  va_list args;
  fprintf(stderr, "%s: ", progname);
  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
  if (errnum != 0)
    fprintf(stderr, ": %s\n", strerror(errnum));
  else
    fputc('\n', stderr);
  if (status != 0)
    exit(status);
}

void child_handler(int sig) {
  int pid, status;
  while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
    if (pid != logpid && !WIFSTOPPED(status) && children > 0)
      children--;
  signal(SIGCHLD, child_handler);
}

int decode(char *name, CODE *table) {
  char *trail;
  int value;
  CODE *row;
  for (row = table; row->c_name; row++)
    if (strcasecmp(name, row->c_name) == 0)
      return (row->c_val);
  if (isdigit(name[0])) {
    value = strtol(name, &trail, 0);
    if (!trail || trail[0] == '\0')
      return value;
  }
  return -1;
}

void droproot(void) {
  char *root, *gids, *uids, *trail;
  uid_t uid;
  gid_t gid;

  if (!droprootprivs)
    return;

  if ((root = getenv("ROOT"))) {
    if (chdir(root))
      error(1, errno, "Unable to chdir to %s", root);
    if (chroot("."))
      error(1, errno, "Unable to chroot to %s", root);
  }

  gids = getenv("GID");
  if (!gids)
    error(1, 0, "$GID not set");
  if (!isdigit(gids[0]))
    error(1, 0, "$GID has invalid value '%s'", gids);
  gid = strtol(gids, &trail, 0);
  if (trail && trail[0] != '\0')
    error(1, 0, "$GID has invalid value '%s'", gids);
  if (setgid(gid) || setgroups(1, &gid))
    error(1, 0, "Unable to setgid to %d", gid);

  uids = getenv("UID");
  if (!uids)
    error(1, 0, "$UID not set");
  if (!isdigit(uids[0]))
    error(1, 0, "$UID has invalid value '%s'", uids);
  uid = strtol(uids, &trail, 0);
  if (trail && trail[0] != '\0')
    error(1, 0, "$UID has invalid value '%s'", uids);
  if (setuid(uid))
    error(1, 0, "Unable to setuid to %d", uid);
}

int startlogger(char *spec) {
  char *logname, *facname, *priname;
  int facility, logpipe[2], pid, priority;
  sigset_t mask_child, mask_restore;

  if (!spec)
    return STDERR_FILENO;

  if (spec[0] == '>') {
    if (spec[1] == '>') {
      for (spec += 2; *spec == '\t' || *spec == ' '; spec++);
      logpipe[1] = open(spec, O_WRONLY | O_CREAT | O_APPEND, 0666);
    } else {
      for (spec += 1; *spec == '\t' || *spec == ' '; spec++);
      logpipe[1] = open(spec, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    }
    if (logpipe[1] < 0)
      error(1, errno, "open %s", spec);
    return logpipe[1];
  }

  if (!(spec = strdup(spec)))
    error(1, errno, "strdup");
  logname = strsep(&spec, ":");
  if (spec && spec[0] != '\0') {
    facname = strsep(&spec, ".");
    priname = spec;
    facility = facname ? decode(facname, facilitynames) : -1;
    priority = priname ? decode(priname, prioritynames) : -1;
  } else {
    facility = LOG_DAEMON;
    priority = LOG_NOTICE;
  }
  if (facility < 0 || priority < 0)
    error(1, 0, "Invalid log specification '%s'", spec);
  openlog(logname, LOG_NDELAY, facility);

  if (pipe(logpipe) < 0)
    error(1, errno, "pipe");

  sigprocmask(SIG_BLOCK, &mask_child, &mask_restore);
  switch (pid = fork()) {
    case -1:
      error(1, errno, "fork");
    case 0: {
      char buffer[1024];
      droproot();
      dup2(logpipe[0], STDIN_FILENO);
      close(STDOUT_FILENO);
      close(STDERR_FILENO);
      close(logpipe[0]);
      close(logpipe[1]);
      if (bgfd >= 0)
        close(bgfd);
      chdir("/");
      while (fgets(buffer, sizeof(buffer), stdin) != NULL) {
        int length = strlen(buffer);
        while (length > 0 && buffer[length - 1] == '\n')
          buffer[--length] = '\0';
        if (length > 0)
          syslog(priority, "%s", buffer);
      }
      closelog();
      exit(0);
    }
    default:
      logpid = pid;
  }
  sigprocmask(SIG_SETMASK, &mask_restore, NULL);
  close(logpipe[0]);
  return logpipe[1];
}

int inetsock(char *portname, int style) {
  char *hostname;
  int numerichost, sock;
  struct addrinfo *addr, hints;

  if (!(portname = strdup(portname)))
    error(1, errno, "strdup");

  if (*portname == '[') {
    int depth;
    hostname = ++portname;
    numerichost = 1;
    for (depth = 1; *portname != ']' || --depth > 0; portname++)
      if (*portname == '\0')
        error(1, 0, "Port specification contains unbalanced '['");
      else if (*portname == '[')
        depth++;
    *portname++ = '\0';
    if (*portname == ':')
      *portname++ = '\0';
    else
      error(1, 0, "Port specification must be in form PORT, HOSTNAME:PORT or "
                  "[IP]:PORT");
  } else {
    hostname = strsep(&portname, ":");
    numerichost = 0;
    if (!portname) {
      portname = hostname;
      hostname = NULL;
    }
  }
  if (hostname && hostname[0] == '\0')
    hostname = NULL;
  if (portname[0] == '\0')
    error(1, 0, "Port specification must be in form PORT, HOSTNAME:PORT or "
                "[IP]:PORT");

  memset(&hints, 0, sizeof(hints));
  hints.ai_flags = AI_PASSIVE | (numerichost ? AI_NUMERICHOST : 0);
#ifdef AI_ADDRCONFIG
  hints.ai_flags |= AI_ADDRCONFIG;
#endif
  hints.ai_socktype = style;
  hints.ai_family = AF_UNSPEC;

  if (getaddrinfo(hostname, portname, &hints, &addr) < 0 || !addr)
    error(1, 0, "Host address or port does not exist");

  for (sock = -1; addr != NULL; addr = addr->ai_next) {
    sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
    if (sock >= 0) {
      static const int one = 1;
      if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0)
        error(1, errno, "setsockopt");
      if (bind(sock, addr->ai_addr, addr->ai_addrlen) == 0) {
        switch (addr->ai_family) {
          case AF_INET:
            if (ntohs(((struct sockaddr_in *) addr->ai_addr)->sin_port) == 0) {
              struct sockaddr_in myaddr;
              socklen_t addrsize = sizeof(myaddr);
              if (getsockname(sock, (struct sockaddr *) &myaddr, &addrsize) == 0)
                printf("%d\n", ntohs(myaddr.sin_port));
            }
            break;
          case AF_INET6:
            if (ntohs(((struct sockaddr_in6 *) addr->ai_addr)->sin6_port) == 0) {
              struct sockaddr_in6 myaddr;
              socklen_t addrsize = sizeof(myaddr);
              if (getsockname(sock, (struct sockaddr *) &myaddr, &addrsize) == 0)
                printf("%d\n", ntohs(myaddr.sin6_port));
            }
            break;
        }
        break;
      }
      close(sock);
      sock = -1;
    }
  }
  if (sock < 0)
    error(1, errno, "creating socket");

  return sock;
}

int localsock(char *path, int style) {
  int sock;
  size_t sasize;
  struct sockaddr_un *sa;
  struct stat st;

  sasize = offsetof(struct sockaddr_un, sun_path) + strlen(path) + 1;
  if (!(sa = (struct sockaddr_un *) malloc(sasize)))
    error(1, errno, "malloc");

  if ((sock = socket(PF_LOCAL, style, 0)) < 0)
    error(1, errno, "socket");

  if (lstat(path, &st) == 0 && S_ISSOCK(st.st_mode))
    unlink(path);

  sa->sun_family = AF_LOCAL;
  strcpy(sa->sun_path, path);
  if (bind(sock, (struct sockaddr *) sa, sasize) < 0)
    error(1, errno, "bind");

  return sock;
}

void acceptloop(int sock, char **cmdv, int verbose, int maxchildren,
                int nodelay) {
  char host[64], port[6];
  int nc;
  sigset_t mask_child, mask_restore;
  struct sockaddr_storage fromaddr, myaddr;
  socklen_t addrsize;

  sigemptyset(&mask_child);
  sigaddset(&mask_child, SIGCHLD);
  while (1) {
    sigprocmask(SIG_BLOCK, &mask_child, &mask_restore);
    while (maxchildren > 0 && children >= maxchildren)
      sigsuspend(&mask_restore);
    sigprocmask(SIG_SETMASK, &mask_restore, NULL);
    addrsize = sizeof(fromaddr);
    nc = accept(sock, (struct sockaddr *) &fromaddr, &addrsize);
    if (nc >= 0) {
      switch (((struct sockaddr *) &fromaddr)->sa_family) {
        case AF_INET:
          setenv("PROTO", "TCP", 1);
          addrsize = sizeof(myaddr);
          if (getsockname(nc, (struct sockaddr *) &myaddr, &addrsize) == 0) {
            inet_ntop(AF_INET, &((struct sockaddr_in *) &myaddr)->sin_addr,
                      host, sizeof(host));
            snprintf(port, sizeof(port), "%d",
                     ntohs(((struct sockaddr_in *) &myaddr)->sin_port));
            setenv("TCPLOCALIP", host, 1);
            setenv("TCPLOCALPORT", port, 1);
          } else {
            unsetenv("TCPLOCALIP");
            unsetenv("TCPLOCALPORT");
          }
          addrsize = sizeof(fromaddr);
          inet_ntop(AF_INET, &((struct sockaddr_in *) &fromaddr)->sin_addr,
                    host, sizeof(host));
          snprintf(port, sizeof(port), "%d",
                   ntohs(((struct sockaddr_in *) &fromaddr)->sin_port));
          setenv("TCPREMOTEIP", host, 1);
          setenv("TCPREMOTEPORT", port, 1);
          if (verbose)
            fprintf(stderr, "Accepted connection from [%s]:%s\n", host, port);
          break;

        case AF_INET6:
          setenv("PROTO", "TCP", 1);
          addrsize = sizeof(myaddr);
          if (getsockname(nc, (struct sockaddr *) &myaddr, &addrsize) == 0) {
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *) &myaddr)->sin6_addr,
                      host, sizeof(host));
            snprintf(port, sizeof(port), "%d",
                     ntohs(((struct sockaddr_in6 *) &myaddr)->sin6_port));
            setenv("TCPLOCALIP", host, 1);
            setenv("TCPLOCALPORT", port, 1);
          } else {
            unsetenv("TCPLOCALIP");
            unsetenv("TCPLOCALPORT");
          }
          addrsize = sizeof(fromaddr);
          inet_ntop(AF_INET6, &((struct sockaddr_in6 *) &fromaddr)->sin6_addr,
                    host, sizeof(host));
          snprintf(port, sizeof(port), "%d",
                   ntohs(((struct sockaddr_in6 *) &fromaddr)->sin6_port));
          setenv("TCPREMOTEIP", host, 1);
          setenv("TCPREMOTEPORT", port, 1);
          if (verbose)
            fprintf(stderr, "Accepted connection from [%s]:%s\n", host, port);
          break;

        default:
          setenv("PROTO", "UNIX-STREAM", 1);
#ifdef SO_PEERCRED
          struct ucred peer;
          char uid[11], gid[11], pid[11];
          socklen_t peersize = sizeof(peer);
          if (getsockopt(nc, SOL_SOCKET, SO_PEERCRED, &peer, &peersize) == 0) {
            if (verbose) 
              fprintf(stderr, "Accepted local connection from pid %d "
                              "(uid = %d, gid = %d)\n",
                      peer.pid, peer.uid, peer.gid);
            snprintf(pid, sizeof(pid), "%d", peer.pid);
            setenv("PEERPID", pid, 1);
            snprintf(uid, sizeof(uid), "%d", peer.uid);
            setenv("PEERUID", uid, 1);
            snprintf(gid, sizeof(gid), "%d", peer.gid);
            setenv("PEERGID", gid, 1);
          } else {
            unsetenv("PEERPID");
            unsetenv("PEERUID");
            unsetenv("PEERGID");
            if (verbose)
              fprintf(stderr, "Accepted local connection\n");
          }
#else
          unsetenv("PEERPID");
          unsetenv("PEERUID");
          unsetenv("PEERGID");
          if (verbose)
            fprintf(stderr, "Accepted local connection\n");
#endif
      }

      if (nodelay) {
        static const int one = 1;
        setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
      }

      sigprocmask(SIG_BLOCK, &mask_child, &mask_restore);
      switch (fork()) {
        case -1:
          fprintf(stderr, "Fork failed: %s\n", strerror(errno));
          break;
        case 0:
          sigprocmask(SIG_SETMASK, &mask_restore, NULL);
          dup2(nc, STDIN_FILENO);
          dup2(nc, STDOUT_FILENO);
          close(nc);
          execvp(cmdv[0], cmdv);
          fprintf(stderr, "Exec failed: %s\n", strerror(errno));
          exit(1);
        default:
          children++;
      }
      sigprocmask(SIG_SETMASK, &mask_restore, NULL);
      close(nc);
    } else {
      fprintf(stderr, "Accept failed: %s\n", strerror(errno));
      sleep(1);
    }
  }
}

void recvloop(int sock, char **cmdv, int verbose) {
  char host[64];
  int flags;
  sigset_t mask_child, mask_restore;
  struct sockaddr_storage fromaddr;
  socklen_t addrsize;

  sigemptyset(&mask_child);
  sigaddset(&mask_child, SIGCHLD);
  while (1) {
    sigprocmask(SIG_BLOCK, &mask_child, &mask_restore);
    while (children > 0)
      sigsuspend(&mask_restore);
    sigprocmask(SIG_SETMASK, &mask_restore, NULL);
    addrsize = sizeof(fromaddr);
    flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
    if (recvfrom(sock, NULL, 0, MSG_PEEK, (struct sockaddr *) &fromaddr,
                 &addrsize) >= 0) {


      switch (((struct sockaddr *) &fromaddr)->sa_family) {
        case AF_INET:
          setenv("PROTO", "UDP", 1);
          if (verbose) {
            inet_ntop(AF_INET, &((struct sockaddr_in *) &fromaddr)->sin_addr,
                      host, sizeof(host));
            fprintf(stderr, "Received initial datagram from [%s]:%d\n", host,
                    ntohs(((struct sockaddr_in *) &fromaddr)->sin_port));
          }
          break;
        case AF_INET6:
          setenv("PROTO", "UDP", 1);
          if (verbose) {
            inet_ntop(AF_INET6,
                      &((struct sockaddr_in6 *) &fromaddr)->sin6_addr,
                      host, sizeof(host));
            fprintf(stderr, "Received initial datagram from [%s]:%d\n", host,
                    ntohs(((struct sockaddr_in6 *) &fromaddr)->sin6_port));
          }
          break;
        default:
          setenv("PROTO", "UNIX-DGRAM", 1);
          if (verbose)
            fprintf(stderr, "Received initial local datagram\n");
      }

      sigprocmask(SIG_BLOCK, &mask_child, &mask_restore);
      switch (fork()) {
        case -1:
          fprintf(stderr, "Fork failed: %s\n", strerror(errno));
          break;
        case 0:
          sigprocmask(SIG_SETMASK, &mask_restore, NULL);
          dup2(sock, STDIN_FILENO);
          dup2(sock, STDOUT_FILENO);
          close(sock);
          execvp(cmdv[0], cmdv);
          fprintf(stderr, "Exec failed: %s\n", strerror(errno));
          exit(1);
        default:
          children++;
      }
      sigprocmask(SIG_SETMASK, &mask_restore, NULL);
    } else if (errno != EAGAIN && errno != EINTR)
      fprintf(stderr, "Recv failed: %s\n", strerror(errno));
  }
}

void superviseloop(char **cmdv, int verbose) {
  int pid, status;

  while (1) {
    if (verbose)
      fprintf(stderr, "Started %s\n", cmdv[0]);

    switch (pid = fork()) {
      case -1:
        fprintf(stderr, "Fork failed: %s\n", strerror(errno));
        break;
      case 0:
        execvp(cmdv[0], cmdv);
        fprintf(stderr, "Exec failed: %s\n", strerror(errno));
        exit(1);
      default:
        waitpid(pid, &status, 0);
        if (verbose && WIFEXITED(status) && WEXITSTATUS(status))
          fprintf(stderr, "%s exited abnormally with status %d\n",
                  cmdv[0], WEXITSTATUS(status));
        else if (verbose && WIFSIGNALED(status))
          fprintf(stderr, "%s was terminated by signal %d\n",
                  cmdv[0], WTERMSIG(status));
    }
  }
}

void writepidfile(char *pidfile) {
  FILE *pidstream;
  if (!pidfile)
    return;
  if ((pidstream = fopen(pidfile, "w"))) {
    fprintf(pidstream, "%d\n", getpid());
    fclose(pidstream);
  } else
    error(1, errno, "fopen %s", pidfile);
}

void usage(char *progname) {
  fprintf(stderr, "\
Usage: %s [OPTIONS] PROG [ARGS]...\n\
Options:\n\
  -i [INTERFACE:]PORT	bind a listening socket in the internet namespace\n\
  -l PATH, -x PATH      bind a listening socket in the local unix namespace\n\
  -s                    create a stream socket (default socket style)\n\
  -d                    create a datagram socket instead of a stream socket\n\
  -t [INTERFACE:]PORT   create a TCP socket: equivalent to -s -i\n\
  -u [INTERFACE:]PORT   create a UDP socket: equivalent to -d -i\n\
  -b BACKLOG            set the listen backlog for a stream socket\n\
  -c MAXCLIENTS         set the maximum number of concurrent connections\n\
                          accepted by a stream socket (default is unlimited)\n\
  -n                    set TCP_NODELAY to disable Nagle's algorithm for TCP\n\
                          stream connections\n\
  -v                    report information about every connection accepted\n\
                          or initial datagram received to stderr or the log\n\
  -B                    fork, establish new session id, redirect stdin and\n\
                          stdout to/from /dev/null if they are attached to a\n\
                          terminal, and run as a daemon in the background\n\
  -L TAG[:FAC.PRI]      start a logger subprocess, redirecting stderr to the\n\
                          system log with tag TAG, facility FAC and priority\n\
                          PRI (defaulting to daemon.notice if unspecified)\n\
  -L >LOGFILE           redirect stderr to create and write to LOGFILE\n\
  -L >>LOGFILE          redirect stderr to append to LOGFILE\n\
  -P PIDFILE            write pid to PIDFILE (after forking if used with -B)\n\
  -S                    supervisor mode: restart PROG whenever it exits\n\
  -U                    after binding the socket, drop privileges to those\n\
                          specified by $UID and $GID, and if $ROOT is set,\n\
                          chroot into that directory\n\
  -V                    print the program version number to stderr and exit\n\
\n\
When a stream socket is specified, listen on it and accept all incoming\n\
connections, executing the given program in a child process with stdin and\n\
stdout attached to the connection socket. Do not wait for the child to exit\n\
before accepting another connection on the listening socket.\n\
\n\
When a datagram socket is specified, wait for an initial datagram to arrive\n\
before launching the given program with stdin and stdout attached to the\n\
listening socket. Until this program exits, don't attempt to check for more\n\
datagrams or spawn another child.\n\
\n\
If none of -i, -l, -u is used, no socket is bound and the given program is\n\
executed immediately, after any background, logging, pidfile and privilege\n\
dropping actions have been completed. This allows use of these facilities\n\
for standalone and non-network services. If the -S option is specified in\n\
this case, a supervisor process restarts the program whenever it exits.\n\
", progname);
  exit(1);
}

int main(int argc, char **argv) {
  char *addrspec = NULL, *logspec = NULL, *pidfile = NULL, **cmdv, *trail;
  enum {null, local, inet} namespace = null;
  int background = 0, backlog = 10, bgpipe[2], maxchildren = 0, nodelay = 0,
      style = SOCK_STREAM, supervise = 0, verbose = 0, logfd, opt, sock;

  setlocale(LC_ALL, "");

  while ((opt = getopt(argc, argv, "i:l:x:t:u:dsb:c:nvBL:P:SUV")) > 0)
    switch (opt) {
      case 'i':
        namespace = inet;
        addrspec = optarg;
        break;
      case 'l':
      case 'x':
        namespace = local;
        addrspec = optarg;
        break;
      case 't':
        namespace = inet;
        addrspec = optarg;
      case 's':
        style = SOCK_STREAM;
        break;
      case 'u':
        namespace = inet;
        addrspec = optarg;
      case 'd':
        style = SOCK_DGRAM;
        break;
      case 'b':
        if (!isdigit(optarg[0]))
          error(1, 0, "-b takes a positive integer argument");
        backlog = strtol(optarg, &trail, 0);
        if ((trail && trail[0] != '\0') || backlog <= 0)
          error(1, 0, "-b takes a positive integer argument");
        break;
      case 'c':
        if (!isdigit(optarg[0]))
          error(1, 0, "-c takes a positive integer argument");
        maxchildren = strtol(optarg, &trail, 0);
        if ((trail && trail[0] != '\0') || maxchildren <= 0)
        error(1, 0, "-c takes a positive integer argument");
        break;
      case 'n':
        nodelay++;
        break;
      case 'v':
        verbose++;
        break;
      case 'B':
        background++;
        break;
      case 'L':
        logspec = optarg;
        break;
      case 'P':
        pidfile = optarg;
        break;
      case 'S':
        supervise++;
        break;
      case 'U':
        droprootprivs++;
        break;
      case 'V':
        fprintf(stderr, "%s %s\n", progname, version);
        fprintf(stderr,
                "Copyright (C) 2006-2009 Chris Webb <chris@arachsys.com>\n");
        exit(0);
      default:
        usage(argv[0]);
    }
  if (!*(cmdv = argv + optind))
    usage(argv[0]);

  if (background) {
    char dummy;
    if (pipe(bgpipe) < 0)
      error(1, errno, "pipe");
    switch (fork()) {
      case -1:
        error(1, errno, "fork");
      case 0:
        break;
      default:
        close(bgpipe[1]);
        read(bgpipe[0], &dummy, 1);
        close(bgpipe[0]);
        exit(0);
    }
  }

  switch (namespace) {
    case local:
      sock = localsock(addrspec, style);
      break;
    case inet:
      sock = inetsock(addrspec, style);
      break;
    default:
      sock = 0;;
  }

  writepidfile(pidfile);
  logfd = startlogger(logspec);
  droproot();

  if (namespace != null && style == SOCK_STREAM) {
    if (listen(sock, backlog) < 0)
      error(1, errno, "listen");
  }

  if (background) {
    int devnull;
    close(bgpipe[0]);
    bgfd = bgpipe[1];
    if ((devnull = open("/dev/null", O_RDWR)) < 0)
      error(1, errno, "open /dev/null");
    if (setsid() == -1)
      error(1, errno, "setsid");
    if (isatty(STDIN_FILENO) || namespace != null)
      dup2(devnull, STDIN_FILENO);
    if (isatty(STDOUT_FILENO) || namespace != null)
      dup2(devnull, STDOUT_FILENO);
    close(devnull);
  }

  if (logfd != STDERR_FILENO) {
    dup2(logfd, STDERR_FILENO);
    close(logfd);
  }
  setvbuf(stderr, NULL, _IONBF, 0);

  if (bgfd >= 0)
    close(bgfd);

  if (namespace == null) {
    if (supervise)
      superviseloop(cmdv, verbose);
    else {
      execvp(cmdv[0], cmdv);
      fprintf(stderr, "Exec %s failed: %s\n", cmdv[0], strerror(errno));
      return 1;
    }
  }

  signal(SIGCHLD, child_handler);
  if (style == SOCK_STREAM)
    acceptloop(sock, cmdv, verbose, maxchildren, nodelay);
  else
    recvloop(sock, cmdv, verbose);
  return 1;
}
