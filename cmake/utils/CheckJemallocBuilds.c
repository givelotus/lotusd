#include <jemalloc.h>

int main(void) {
    /* malloc alone can link against libc even when jemalloc is unusable. */
    const char *version = 0;
    size_t size = sizeof(version);
    void *ptr = mallocx(42, 0);
    int result = mallctl("version", &version, &size, 0, 0);
    dallocx(ptr, 0);
    return result;
}
