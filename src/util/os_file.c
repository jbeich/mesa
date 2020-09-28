/*
 * Copyright 2019 Intel Corporation
 * SPDX-License-Identifier: MIT
 */

#include "os_file.h"
#include "detect_os.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>

#if DETECT_OS_WINDOWS
#include <io.h>
#define open _open
#define fdopen _fdopen
#define O_CREAT _O_CREAT
#define O_EXCL _O_EXCL
#define O_WRONLY _O_WRONLY
#else
#include <unistd.h>
#ifndef F_DUPFD_CLOEXEC
#define F_DUPFD_CLOEXEC 1030
#endif
#endif


FILE *
os_file_create_unique(const char *filename, int filemode)
{
   int fd = open(filename, O_CREAT | O_EXCL | O_WRONLY, filemode);
   if (fd == -1)
      return NULL;
   return fdopen(fd, "w");
}


#if DETECT_OS_WINDOWS
int
os_dupfd_cloexec(int fd)
{
   /*
    * On Windows child processes don't inherit handles by default:
    * https://devblogs.microsoft.com/oldnewthing/20111216-00/?p=8873
    */
   return dup(fd);
}
#else
int
os_dupfd_cloexec(int fd)
{
   int minfd = 3;
   int newfd = fcntl(fd, F_DUPFD_CLOEXEC, minfd);

   if (newfd >= 0)
      return newfd;

   if (errno != EINVAL)
      return -1;

   newfd = fcntl(fd, F_DUPFD, minfd);

   if (newfd < 0)
      return -1;

   long flags = fcntl(newfd, F_GETFD);
   if (flags == -1) {
      close(newfd);
      return -1;
   }

   if (fcntl(newfd, F_SETFD, flags | FD_CLOEXEC) == -1) {
      close(newfd);
      return -1;
   }

   return newfd;
}
#endif

#include <fcntl.h>
#include <sys/stat.h>

#if DETECT_OS_WINDOWS
typedef ptrdiff_t ssize_t;
#endif

static ssize_t
readN(int fd, char *buf, size_t len)
{
   /* err was initially set to -ENODATA but in some BSD systems
    * ENODATA is not defined and ENOATTR is used instead.
    * As err is not returned by any function it can be initialized
    * to -EFAULT that exists everywhere.
    */
   int err = -EFAULT;
   size_t total = 0;
   do {
      ssize_t ret = read(fd, buf + total, len - total);

      if (ret < 0)
         ret = -errno;

      if (ret == -EINTR || ret == -EAGAIN)
         continue;

      if (ret <= 0) {
         err = ret;
         break;
      }

      total += ret;
   } while (total != len);

   return total ? (ssize_t)total : err;
}

#ifndef O_BINARY
/* Unix makes no distinction between text and binary files. */
#define O_BINARY 0
#endif

char *
os_read_file(const char *filename, size_t *size)
{
   /* Note that this also serves as a slight margin to avoid a 2x grow when
    * the file is just a few bytes larger when we read it than when we
    * fstat'ed it.
    * The string's NULL terminator is also included in here.
    */
   size_t len = 64;

   int fd = open(filename, O_RDONLY | O_BINARY);
   if (fd == -1) {
      /* errno set by open() */
      return NULL;
   }

   /* Pre-allocate a buffer at least the size of the file if we can read
    * that information.
    */
   struct stat stat;
   if (fstat(fd, &stat) == 0)
      len += stat.st_size;

   char *buf = malloc(len);
   if (!buf) {
      close(fd);
      errno = -ENOMEM;
      return NULL;
   }

   ssize_t actually_read;
   size_t offset = 0, remaining = len - 1;
   while ((actually_read = readN(fd, buf + offset, remaining)) == (ssize_t)remaining) {
      char *newbuf = realloc(buf, 2 * len);
      if (!newbuf) {
         free(buf);
         close(fd);
         errno = -ENOMEM;
         return NULL;
      }

      buf = newbuf;
      len *= 2;
      offset += actually_read;
      remaining = len - offset - 1;
   }

   close(fd);

   if (actually_read > 0)
      offset += actually_read;

   /* Final resize to actual size */
   len = offset + 1;
   char *newbuf = realloc(buf, len);
   if (!newbuf) {
      free(buf);
      errno = -ENOMEM;
      return NULL;
   }
   buf = newbuf;

   buf[offset] = '\0';

   if (size)
      *size = offset;

   return buf;
}

#if DETECT_OS_LINUX

#include <sys/syscall.h>
#include <unistd.h>

/* copied from <linux/kcmp.h> */
#define KCMP_FILE 0

int
os_same_file_description(int fd1, int fd2)
{
   pid_t pid = getpid();

   /* Same file descriptor trivially implies same file description */
   if (fd1 == fd2)
      return 0;

   return syscall(SYS_kcmp, pid, pid, KCMP_FILE, fd1, fd2);
}

#elif DETECT_OS_BSD

#include "macros.h" /* ARRAY_SIZE */

#include <sys/sysctl.h>
#if DETECT_OS_DRAGONFLY
#include <sys/kinfo.h>
#elif DETECT_OS_FREEBSD
#include <sys/file.h>
#endif

#if DETECT_OS_DRAGONFLY
typedef struct kinfo_file kfile_t;
typedef void *kfile_addr_t;
#define KFILE_PID(x) x.f_pid
#define KFILE_FD(x) x.f_fd
#define KFILE_ADDR(x) x.f_file
#elif DETECT_OS_FREEBSD
typedef struct xfile kfile_t;
#if __FreeBSD__ < 12
/* r335979 broke `struct xfile` ABI, so at least make it compile */
typedef void *kvaddr_t;
#endif
typedef kvaddr_t kfile_addr_t;
#define KFILE_PID(x) x.xf_pid
#define KFILE_FD(x) x.xf_fd
#define KFILE_ADDR(x) x.xf_file
#elif DETECT_OS_NETBSD
#undef KERN_FILE
#define KERN_FILE KERN_FILE2
typedef struct kinfo_file kfile_t;
typedef uint64_t kfile_addr_t;
#define KFILE_FD(x) x.ki_fd
#define KFILE_ADDR(x) x.ki_fileaddr
#elif DETECT_OS_OPENBSD
typedef struct kinfo_file kfile_t;
typedef uint64_t kfile_addr_t;
#define KFILE_FD(x) x.fd_fd
#define KFILE_ADDR(x) x.f_fileaddr
#endif

int
os_same_file_description(int fd1, int fd2)
{
   /* Same file descriptor trivially implies same file description */
   if (fd1 == fd2)
      return 0;

   pid_t pid = getpid();
   int mib[] = {
     CTL_KERN,
     KERN_FILE,
#if DETECT_OS_NETBSD || DETECT_OS_OPENBSD
     KERN_FILE_BYPID,
     pid,
     sizeof(kfile_t),
     0,
#endif
   };
   size_t len;
   if (sysctl(mib, ARRAY_SIZE(mib), NULL, &len, NULL, 0))
      return -1;
   kfile_t *kf = malloc(len);
   int count = len / sizeof(*kf);
#if DETECT_OS_NETBSD || DETECT_OS_OPENBSD
   mib[5] = count;
#endif
   if (sysctl(mib, ARRAY_SIZE(mib), kf, &len, NULL, 0))
      return -1;

   kfile_addr_t fd1_addr = 0, fd2_addr = 0;
   for (int i = 0; i < count; i++) {
#if DETECT_OS_DRAGONFLY || DETECT_OS_FREEBSD
      if (pid != KFILE_PID(kf[i]))
         continue;
#endif
      if (fd1 == KFILE_FD(kf[i]))
         fd1_addr = KFILE_ADDR(kf[i]);
      if (fd2 == KFILE_FD(kf[i]))
         fd2_addr = KFILE_ADDR(kf[i]);
   }
   free(kf);

   if (fd1_addr == 0 || fd2_addr == 0)
       return -1;

   return (fd1_addr < fd2_addr) | ((fd1_addr > fd2_addr) << 1);
}

#else

int
os_same_file_description(int fd1, int fd2)
{
   /* Same file descriptor trivially implies same file description */
   if (fd1 == fd2)
      return 0;

   /* Otherwise we can't tell */
   return -1;
}

#endif
