// DYLD interposer: counts file syscalls on blocks/blk*.dat and blocks/rev*.dat.
// Counters are written to $IOCOUNT_OUT (append) on SIGUSR2 and then reset.
#include <dlfcn.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAXFD 65536
static _Atomic unsigned char tracked[MAXFD];
static _Atomic unsigned long c_open, c_close, c_read, c_pread, c_lseek, c_fstat, c_mmap, c_munmap, b_read;

static int is_blockfile(const char *p) {
    if (!p) return 0;
    const char *s = strstr(p, "/blocks/");
    if (!s) return 0;
    s += 8;
    return (strncmp(s, "blk", 3) == 0 || strncmp(s, "rev", 3) == 0) && strstr(s, ".dat");
}
static void track(int fd, const char *p) {
    if (fd >= 0 && fd < MAXFD) {
        int t = is_blockfile(p);
        atomic_store(&tracked[fd], t);
        if (t) atomic_fetch_add(&c_open, 1);
    }
}
static int tr(int fd) { return fd >= 0 && fd < MAXFD && atomic_load(&tracked[fd]); }

extern int open_nocancel(const char *, int, ...) __asm("_open$NOCANCEL");
extern int close_nocancel(int) __asm("_close$NOCANCEL");
extern ssize_t read_nocancel(int, void *, size_t) __asm("_read$NOCANCEL");
extern ssize_t pread_nocancel(int, void *, size_t, off_t) __asm("_pread$NOCANCEL");

static int my_open(const char *p, int f, ...) {
    mode_t m = 0; if (f & O_CREAT) { va_list a; va_start(a, f); m = va_arg(a, int); va_end(a); }
    int fd = open(p, f, m); track(fd, p); return fd;
}
static int my_open_nc(const char *p, int f, ...) {
    mode_t m = 0; if (f & O_CREAT) { va_list a; va_start(a, f); m = va_arg(a, int); va_end(a); }
    int fd = open_nocancel(p, f, m); track(fd, p); return fd;
}
static int my_openat(int d, const char *p, int f, ...) {
    mode_t m = 0; if (f & O_CREAT) { va_list a; va_start(a, f); m = va_arg(a, int); va_end(a); }
    int fd = openat(d, p, f, m); track(fd, p); return fd;
}
static int my_close(int fd) { if (tr(fd)) { atomic_fetch_add(&c_close, 1); atomic_store(&tracked[fd], 0);} return close(fd); }
static int my_close_nc(int fd) { if (tr(fd)) { atomic_fetch_add(&c_close, 1); atomic_store(&tracked[fd], 0);} return close_nocancel(fd); }
static ssize_t my_read(int fd, void *b, size_t n) { ssize_t r = read(fd, b, n); if (tr(fd)) { atomic_fetch_add(&c_read, 1); if (r > 0) atomic_fetch_add(&b_read, r);} return r; }
static ssize_t my_read_nc(int fd, void *b, size_t n) { ssize_t r = read_nocancel(fd, b, n); if (tr(fd)) { atomic_fetch_add(&c_read, 1); if (r > 0) atomic_fetch_add(&b_read, r);} return r; }
static ssize_t my_pread(int fd, void *b, size_t n, off_t o) { ssize_t r = pread(fd, b, n, o); if (tr(fd)) { atomic_fetch_add(&c_pread, 1); if (r > 0) atomic_fetch_add(&b_read, r);} return r; }
static ssize_t my_pread_nc(int fd, void *b, size_t n, off_t o) { ssize_t r = pread_nocancel(fd, b, n, o); if (tr(fd)) { atomic_fetch_add(&c_pread, 1); if (r > 0) atomic_fetch_add(&b_read, r);} return r; }
static off_t my_lseek(int fd, off_t o, int w) { if (tr(fd)) atomic_fetch_add(&c_lseek, 1); return lseek(fd, o, w); }
static int my_fstat(int fd, struct stat *s) { if (tr(fd)) atomic_fetch_add(&c_fstat, 1); return fstat(fd, s); }
static void *my_mmap(void *a, size_t l, int p, int f, int fd, off_t o) { if (tr(fd)) atomic_fetch_add(&c_mmap, 1); return mmap(a, l, p, f, fd, o); }

#define INTERPOSE(n, o) __attribute__((used)) static struct { const void *r; const void *orig; } _ip_##n __attribute__((section("__DATA,__interpose"))) = { (const void *)&n, (const void *)&o };
INTERPOSE(my_open, open)
INTERPOSE(my_open_nc, open_nocancel)
INTERPOSE(my_openat, openat)
INTERPOSE(my_close, close)
INTERPOSE(my_close_nc, close_nocancel)
INTERPOSE(my_read, read)
INTERPOSE(my_read_nc, read_nocancel)
INTERPOSE(my_pread, pread)
INTERPOSE(my_pread_nc, pread_nocancel)
INTERPOSE(my_lseek, lseek)
INTERPOSE(my_fstat, fstat)
INTERPOSE(my_mmap, mmap)

static void dump(int sig) {
    (void)sig;
    const char *out = getenv("IOCOUNT_OUT");
    if (!out) return;
    char buf[512];
    int n = snprintf(buf, sizeof buf,
        "{\"open\":%lu,\"close\":%lu,\"read\":%lu,\"pread\":%lu,\"lseek\":%lu,\"fstat\":%lu,\"mmap\":%lu,\"bytes\":%lu}\n",
        atomic_exchange(&c_open, 0), atomic_exchange(&c_close, 0), atomic_exchange(&c_read, 0),
        atomic_exchange(&c_pread, 0), atomic_exchange(&c_lseek, 0), atomic_exchange(&c_fstat, 0),
        atomic_exchange(&c_mmap, 0), atomic_exchange(&b_read, 0));
    int fd = open(out, O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (fd >= 0) { write(fd, buf, n); close(fd); }
}
__attribute__((constructor)) static void init(void) {
    struct sigaction sa; memset(&sa, 0, sizeof sa); sa.sa_handler = dump; sa.sa_flags = SA_RESTART;
    sigaction(SIGUSR2, &sa, NULL);
}
