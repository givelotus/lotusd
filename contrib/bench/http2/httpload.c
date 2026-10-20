// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/*
 * httpload: a small closed-loop HTTP load generator over TLS, for comparing
 * HTTP/1.1 and HTTP/2 against the node's HTTP server.
 *
 *   httpload --port P [--host 127.0.0.1] --proto h1|h2 --connections N
 *            [--streams S] [--seconds T] [--path /] [--method POST]
 *            [--body STRING] [--header "Name: value"]...
 *
 * h1: N connections (ALPN http/1.1), one request in flight on each.
 * h2: N connections (ALPN h2), S concurrent streams on each.
 * One thread per connection; every response must be a 200. Prints one JSON
 * object: requests, errors, seconds, rps, latency percentiles (ms), and
 * response body bytes.
 *
 * Built by run.py: cc -O2 httpload.c $(pkg-config --cflags --libs openssl
 * libnghttp2) -lpthread; without nghttp2 add -DNO_HTTP2 (h1 only).
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#ifndef NO_HTTP2
#include <nghttp2/nghttp2.h>
#endif

#define MAX_HEADERS 16
#define MAX_LATENCIES (1 << 22)

static const char *g_host = "127.0.0.1";
static int g_port = 0;
static int g_h2 = 0;
static int g_connections = 1;
static int g_streams = 1;
static double g_seconds = 10;
static const char *g_path = "/";
static const char *g_method = "POST";
static const char *g_body = "";
static const char *g_headers[MAX_HEADERS];
static int g_nheaders = 0;

static SSL_CTX *g_ctx;
static double g_deadline;

static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint64_t g_requests, g_errors, g_bytes;
static double *g_latencies;
static size_t g_nlat;

static double Now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void Record(double latency, uint64_t bytes, int ok) {
    pthread_mutex_lock(&g_mutex);
    if (ok) {
        ++g_requests;
        g_bytes += bytes;
        if (g_nlat < MAX_LATENCIES) {
            g_latencies[g_nlat++] = latency;
        }
    } else {
        ++g_errors;
    }
    pthread_mutex_unlock(&g_mutex);
}

static SSL *Connect(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(g_port);
    inet_pton(AF_INET, g_host, &sa.sin_addr);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        perror("connect");
        close(fd);
        return NULL;
    }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    SSL *ssl = SSL_new(g_ctx);
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, "localhost");
    if (SSL_connect(ssl) != 1) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(fd);
        return NULL;
    }
    const unsigned char *alpn = NULL;
    unsigned int alpn_len = 0;
    SSL_get0_alpn_selected(ssl, &alpn, &alpn_len);
    const char *want = g_h2 ? "h2" : "http/1.1";
    if (alpn_len != strlen(want) || memcmp(alpn, want, alpn_len) != 0) {
        fprintf(stderr, "server did not select %s\n", want);
        SSL_free(ssl);
        close(fd);
        return NULL;
    }
    return ssl;
}

static void Disconnect(SSL *ssl) {
    int fd = SSL_get_fd(ssl);
    SSL_free(ssl);
    close(fd);
}

/* ---- HTTP/1.1 ---- */

static void *RunH1(void *arg) {
    (void)arg;
    SSL *ssl = Connect();
    if (!ssl) {
        Record(0, 0, 0);
        return NULL;
    }
    char req[8192];
    int n =
        snprintf(req, sizeof(req),
                 "%s %s HTTP/1.1\r\nHost: localhost\r\nContent-Length: %zu\r\n",
                 g_method, g_path, strlen(g_body));
    for (int i = 0; i < g_nheaders; ++i) {
        n += snprintf(req + n, sizeof(req) - n, "%s\r\n", g_headers[i]);
    }
    n += snprintf(req + n, sizeof(req) - n, "\r\n%s", g_body);
    size_t cap = 1 << 16;
    char *buf = malloc(cap);
    while (Now() < g_deadline) {
        const double start = Now();
        if (SSL_write(ssl, req, n) != n) {
            Record(0, 0, 0);
            break;
        }
        size_t have = 0;
        long header_end = -1, content_length = -1;
        int status = 0;
        for (;;) {
            if (header_end >= 0 && content_length >= 0 &&
                have >= (size_t)header_end + (size_t)content_length) {
                break;
            }
            if (have + 1 >= cap) {
                cap *= 2;
                buf = realloc(buf, cap);
            }
            int r = SSL_read(ssl, buf + have, (int)(cap - have - 1));
            if (r <= 0) {
                status = -1;
                break;
            }
            have += (size_t)r;
            buf[have] = 0; // for strcasestr()
            if (header_end < 0) {
                char *end = memmem(buf, have, "\r\n\r\n", 4);
                if (end) {
                    header_end = end - buf + 4;
                    status = atoi(buf + 9);
                    char *cl = strcasestr(buf, "\r\ncontent-length:");
                    content_length =
                        (cl && cl < end) ? strtol(cl + 17, NULL, 10) : 0;
                }
            }
        }
        if (status != 200) {
            Record(0, 0, 0);
            if (status < 0) {
                break;
            }
            continue;
        }
        Record(Now() - start, (uint64_t)content_length, 1);
        // Keep-alive: nothing is pipelined, so the buffer is now empty.
    }
    free(buf);
    Disconnect(ssl);
    return NULL;
}

/* ---- HTTP/2 ---- */

#ifndef NO_HTTP2
struct H2Stream {
    double start;
    uint64_t bytes;
    int status;
};

struct H2Conn {
    SSL *ssl;
    nghttp2_session *session;
    int in_flight;
    int failed;
    struct H2Stream *streams; // indexed by (stream_id - 1) / 2, grown
    size_t nstreams;
};

static struct H2Stream *H2Get(struct H2Conn *c, int32_t id) {
    size_t i = (size_t)(id - 1) / 2;
    if (i >= c->nstreams) {
        size_t n = c->nstreams ? c->nstreams * 2 : 1024;
        while (n <= i) {
            n *= 2;
        }
        c->streams = realloc(c->streams, n * sizeof(*c->streams));
        memset(c->streams + c->nstreams, 0,
               (n - c->nstreams) * sizeof(*c->streams));
        c->nstreams = n;
    }
    return &c->streams[i];
}

static nghttp2_ssize H2Send(nghttp2_session *s, const uint8_t *data, size_t len,
                            int flags, void *u) {
    (void)s;
    (void)flags;
    struct H2Conn *c = u;
    int r = SSL_write(c->ssl, data, (int)len);
    if (r <= 0) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return r;
}

static int H2Header(nghttp2_session *s, const nghttp2_frame *f,
                    const uint8_t *name, size_t nl, const uint8_t *value,
                    size_t vl, uint8_t flags, void *u) {
    (void)s;
    (void)flags;
    (void)vl;
    if (f->hd.type == NGHTTP2_HEADERS && nl == 7 &&
        memcmp(name, ":status", 7) == 0) {
        H2Get(u, f->hd.stream_id)->status = atoi((const char *)value);
    }
    return 0;
}

static int H2Data(nghttp2_session *s, uint8_t flags, int32_t id,
                  const uint8_t *data, size_t len, void *u) {
    (void)s;
    (void)flags;
    (void)data;
    H2Get(u, id)->bytes += len;
    return 0;
}

static int H2Close(nghttp2_session *s, int32_t id, uint32_t err, void *u) {
    (void)s;
    struct H2Conn *c = u;
    struct H2Stream *st = H2Get(c, id);
    Record(Now() - st->start, st->bytes, err == 0 && st->status == 200);
    --c->in_flight;
    return 0;
}

static nghttp2_ssize H2ReadBody(nghttp2_session *s, int32_t id, uint8_t *buf,
                                size_t len, uint32_t *flags,
                                nghttp2_data_source *src, void *u) {
    (void)s;
    (void)id;
    (void)src;
    (void)u;
    size_t n = strlen(g_body);
    if (n > len) {
        n = len; // bodies are small here
    }
    memcpy(buf, g_body, n);
    *flags |= NGHTTP2_DATA_FLAG_EOF;
    return (nghttp2_ssize)n;
}

static void H2Submit(struct H2Conn *c) {
    nghttp2_nv nva[4 + MAX_HEADERS];
    char names[MAX_HEADERS][256], values[MAX_HEADERS][4096];
    int n = 0;
#define NV(N, V)                                                               \
    nva[n++] = (nghttp2_nv) {                                                  \
        (uint8_t *)(N), (uint8_t *)(V), strlen(N), strlen(V),                  \
            NGHTTP2_NV_FLAG_NONE                                               \
    }
    NV(":method", g_method);
    NV(":scheme", "https");
    NV(":authority", "localhost");
    NV(":path", g_path);
    for (int i = 0; i < g_nheaders; ++i) {
        const char *colon = strchr(g_headers[i], ':');
        size_t nl = (size_t)(colon - g_headers[i]);
        for (size_t k = 0; k < nl; ++k) {
            char ch = g_headers[i][k];
            names[i][k] = (ch >= 'A' && ch <= 'Z') ? ch - 'A' + 'a' : ch;
        }
        names[i][nl] = 0;
        const char *v = colon + 1;
        while (*v == ' ') {
            ++v;
        }
        snprintf(values[i], sizeof(values[i]), "%s", v);
        NV(names[i], values[i]);
    }
#undef NV
    nghttp2_data_provider2 prov = {.read_callback = H2ReadBody};
    int32_t id = nghttp2_submit_request2(c->session, NULL, nva, (size_t)n,
                                         strlen(g_body) ? &prov : NULL, NULL);
    if (id < 0) {
        c->failed = 1;
        return;
    }
    struct H2Stream *st = H2Get(c, id);
    st->start = Now();
    st->bytes = 0;
    st->status = 0;
    ++c->in_flight;
}

static void *RunH2(void *arg) {
    (void)arg;
    struct H2Conn c;
    memset(&c, 0, sizeof(c));
    c.ssl = Connect();
    if (!c.ssl) {
        Record(0, 0, 0);
        return NULL;
    }
    nghttp2_session_callbacks *cbs;
    nghttp2_session_callbacks_new(&cbs);
    nghttp2_session_callbacks_set_send_callback2(cbs, H2Send);
    nghttp2_session_callbacks_set_on_header_callback(cbs, H2Header);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, H2Data);
    nghttp2_session_callbacks_set_on_stream_close_callback(cbs, H2Close);
    nghttp2_session_client_new(&c.session, cbs, &c);
    nghttp2_session_callbacks_del(cbs);
    nghttp2_settings_entry iv[] = {
        {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 16 << 20},
        {NGHTTP2_SETTINGS_ENABLE_PUSH, 0},
    };
    nghttp2_submit_settings(c.session, NGHTTP2_FLAG_NONE, iv, 2);
    nghttp2_session_set_local_window_size(c.session, NGHTTP2_FLAG_NONE, 0,
                                          64 << 20);
    uint8_t buf[1 << 16];
    while (!c.failed) {
        const int running = Now() < g_deadline;
        while (running && c.in_flight < g_streams && !c.failed) {
            H2Submit(&c);
        }
        if (!running && c.in_flight == 0) {
            break;
        }
        if (nghttp2_session_send(c.session) != 0) {
            break;
        }
        int r = SSL_read(c.ssl, buf, sizeof(buf));
        if (r <= 0) {
            break;
        }
        if (nghttp2_session_mem_recv2(c.session, buf, (size_t)r) < 0) {
            break;
        }
    }
    if (c.in_flight > 0) {
        pthread_mutex_lock(&g_mutex);
        g_errors += (uint64_t)c.in_flight;
        pthread_mutex_unlock(&g_mutex);
    }
    nghttp2_session_del(c.session);
    free(c.streams);
    Disconnect(c.ssl);
    return NULL;
}
#endif

static int CompareDouble(const void *a, const void *b) {
    const double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y;
}

static double Percentile(double p) {
    if (g_nlat == 0) {
        return 0;
    }
    size_t i = (size_t)(p * (double)(g_nlat - 1));
    return g_latencies[i] * 1000;
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; ++i) {
        const char *a = argv[i];
        const char *v = i + 1 < argc ? argv[i + 1] : "";
        if (!strcmp(a, "--host")) {
            g_host = v, ++i;
        } else if (!strcmp(a, "--port")) {
            g_port = atoi(v), ++i;
        } else if (!strcmp(a, "--proto")) {
            g_h2 = !strcmp(v, "h2"), ++i;
        } else if (!strcmp(a, "--connections")) {
            g_connections = atoi(v), ++i;
        } else if (!strcmp(a, "--streams")) {
            g_streams = atoi(v), ++i;
        } else if (!strcmp(a, "--seconds")) {
            g_seconds = atof(v), ++i;
        } else if (!strcmp(a, "--path")) {
            g_path = v, ++i;
        } else if (!strcmp(a, "--method")) {
            g_method = v, ++i;
        } else if (!strcmp(a, "--body")) {
            g_body = v, ++i;
        } else if (!strcmp(a, "--header") && g_nheaders < MAX_HEADERS) {
            g_headers[g_nheaders++] = v, ++i;
        } else {
            fprintf(stderr, "unknown argument %s\n", a);
            return 2;
        }
    }
#ifdef NO_HTTP2
    if (g_h2) {
        fprintf(stderr, "built without nghttp2: h2 unavailable\n");
        return 3;
    }
#endif
    if (g_port == 0 || g_connections < 1 || g_streams < 1) {
        fprintf(stderr, "usage: see the comment at the top of httpload.c\n");
        return 2;
    }
    g_latencies = malloc(MAX_LATENCIES * sizeof(double));
    g_ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_verify(g_ctx, SSL_VERIFY_NONE, NULL);
    static const unsigned char h2[] = "\x02h2", h1[] = "\x08http/1.1";
    if (g_h2) {
        SSL_CTX_set_alpn_protos(g_ctx, h2, 3);
    } else {
        SSL_CTX_set_alpn_protos(g_ctx, h1, 9);
    }
    pthread_t *threads = calloc((size_t)g_connections, sizeof(pthread_t));
    const double start = Now();
    g_deadline = start + g_seconds;
    for (int i = 0; i < g_connections; ++i) {
#ifndef NO_HTTP2
        pthread_create(&threads[i], NULL, g_h2 ? RunH2 : RunH1, NULL);
#else
        pthread_create(&threads[i], NULL, RunH1, NULL);
#endif
    }
    for (int i = 0; i < g_connections; ++i) {
        pthread_join(threads[i], NULL);
    }
    const double elapsed = Now() - start;
    qsort(g_latencies, g_nlat, sizeof(double), CompareDouble);
    printf("{\"proto\": \"%s\", \"connections\": %d, \"streams\": %d, "
           "\"requests\": %llu, \"errors\": %llu, \"seconds\": %.3f, "
           "\"rps\": %.1f, \"p50_ms\": %.3f, \"p90_ms\": %.3f, "
           "\"p99_ms\": %.3f, \"body_bytes\": %llu}\n",
           g_h2 ? "h2" : "h1", g_connections, g_h2 ? g_streams : 1,
           (unsigned long long)g_requests, (unsigned long long)g_errors,
           elapsed, (double)g_requests / elapsed, Percentile(0.5),
           Percentile(0.9), Percentile(0.99), (unsigned long long)g_bytes);
    return g_errors > 0 && g_requests == 0 ? 1 : 0;
}
