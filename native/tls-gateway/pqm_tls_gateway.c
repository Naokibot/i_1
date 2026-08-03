#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define BUFFER_SIZE 32768
#define CONFIG_LIMIT (2 * 1024 * 1024)
#define VALUE_LIMIT 4096

struct gateway_config {
    char listen[256];
    char upstream[256];
    char server_name[256];
    char certificate[VALUE_LIMIT];
    char private_key[VALUE_LIMIT];
    char ca_file[VALUE_LIMIT];
    char groups[VALUE_LIMIT];
    char provider[128];
    char provider_path[VALUE_LIMIT];
    char telemetry_file[VALUE_LIMIT];
    bool verify_upstream;
};

struct gateway_runtime {
    struct gateway_config config;
    SSL_CTX *listener_ctx;
    SSL_CTX *upstream_ctx;
    int listen_fd;
    pthread_mutex_t telemetry_lock;
    pthread_mutex_t connection_lock;
    pthread_cond_t connection_drained;
    size_t active_connections;
    OSSL_PROVIDER *default_provider;
    OSSL_PROVIDER *configured_provider;
};

struct connection_args {
    struct gateway_runtime *runtime;
    int client_fd;
};

static volatile sig_atomic_t stop_requested = 0;
static volatile sig_atomic_t signal_listen_fd = -1;

static void on_signal(int signal_number) {
    (void)signal_number;
    stop_requested = 1;
    if (signal_listen_fd >= 0) {
        close((int)signal_listen_fd);
        signal_listen_fd = -1;
    }
}

static void openssl_error(const char *message) {
    fprintf(stderr, "%s\n", message);
    ERR_print_errors_fp(stderr);
}

static void connection_acquire(struct gateway_runtime *runtime) {
    pthread_mutex_lock(&runtime->connection_lock);
    runtime->active_connections++;
    pthread_mutex_unlock(&runtime->connection_lock);
}

static void connection_release(struct gateway_runtime *runtime) {
    pthread_mutex_lock(&runtime->connection_lock);
    if (runtime->active_connections > 0) {
        runtime->active_connections--;
    }
    if (runtime->active_connections == 0) {
        pthread_cond_broadcast(&runtime->connection_drained);
    }
    pthread_mutex_unlock(&runtime->connection_lock);
}

static void wait_for_connections(struct gateway_runtime *runtime) {
    pthread_mutex_lock(&runtime->connection_lock);
    while (runtime->active_connections != 0) {
        pthread_cond_wait(&runtime->connection_drained, &runtime->connection_lock);
    }
    pthread_mutex_unlock(&runtime->connection_lock);
}

static char *read_file(const char *path, size_t *length_out) {
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        return NULL;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return NULL;
    }
    long length = ftell(file);
    if (length < 0 || length > CONFIG_LIMIT) {
        fclose(file);
        errno = EFBIG;
        return NULL;
    }
    rewind(file);
    char *buffer = calloc((size_t)length + 1, 1);
    if (buffer == NULL) {
        fclose(file);
        return NULL;
    }
    size_t read_length = fread(buffer, 1, (size_t)length, file);
    fclose(file);
    if (read_length != (size_t)length) {
        free(buffer);
        errno = EIO;
        return NULL;
    }
    *length_out = read_length;
    return buffer;
}

static const char *skip_space(const char *cursor) {
    while (*cursor == ' ' || *cursor == '\t' || *cursor == '\r' || *cursor == '\n') {
        cursor++;
    }
    return cursor;
}

static bool json_find_key(const char *json, const char *key, const char **value_out) {
    char pattern[256];
    int written = snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    if (written < 0 || (size_t)written >= sizeof(pattern)) {
        return false;
    }
    const char *cursor = strstr(json, pattern);
    if (cursor == NULL) {
        return false;
    }
    cursor += strlen(pattern);
    cursor = skip_space(cursor);
    if (*cursor != ':') {
        return false;
    }
    cursor = skip_space(cursor + 1);
    *value_out = cursor;
    return true;
}

static bool json_string(const char *json, const char *key, char *out, size_t out_size) {
    const char *cursor;
    if (!json_find_key(json, key, &cursor) || *cursor != '"') {
        return false;
    }
    cursor++;
    size_t used = 0;
    while (*cursor != '\0' && *cursor != '"') {
        char value = *cursor++;
        if (value == '\\') {
            value = *cursor++;
            switch (value) {
                case 'n': value = '\n'; break;
                case 'r': value = '\r'; break;
                case 't': value = '\t'; break;
                case '\\': break;
                case '"': break;
                default: return false;
            }
        }
        if (used + 1 >= out_size) {
            return false;
        }
        out[used++] = value;
    }
    if (*cursor != '"') {
        return false;
    }
    out[used] = '\0';
    return true;
}

static bool json_bool(const char *json, const char *key, bool *out) {
    const char *cursor;
    if (!json_find_key(json, key, &cursor)) {
        return false;
    }
    if (strncmp(cursor, "true", 4) == 0) {
        *out = true;
        return true;
    }
    if (strncmp(cursor, "false", 5) == 0) {
        *out = false;
        return true;
    }
    return false;
}

static bool json_string_array_colon_list(const char *json, const char *key, char *out, size_t out_size) {
    const char *cursor;
    if (!json_find_key(json, key, &cursor) || *cursor != '[') {
        return false;
    }
    cursor++;
    size_t used = 0;
    bool first = true;
    for (;;) {
        cursor = skip_space(cursor);
        if (*cursor == ']') {
            out[used] = '\0';
            return true;
        }
        if (*cursor != '"') {
            return false;
        }
        cursor++;
        if (!first) {
            if (used + 1 >= out_size) {
                return false;
            }
            out[used++] = ':';
        }
        while (*cursor != '\0' && *cursor != '"') {
            if (*cursor == '\\') {
                return false;
            }
            if (used + 1 >= out_size) {
                return false;
            }
            out[used++] = *cursor++;
        }
        if (*cursor != '"') {
            return false;
        }
        cursor++;
        first = false;
        cursor = skip_space(cursor);
        if (*cursor == ',') {
            cursor++;
            continue;
        }
        if (*cursor == ']') {
            out[used] = '\0';
            return true;
        }
        return false;
    }
}

static bool load_config(const char *path, struct gateway_config *config) {
    memset(config, 0, sizeof(*config));
    snprintf(config->provider, sizeof(config->provider), "default");
    snprintf(config->telemetry_file, sizeof(config->telemetry_file), "gateway-telemetry.jsonl");
    config->verify_upstream = true;

    size_t length = 0;
    char *json = read_file(path, &length);
    if (json == NULL) {
        perror("read config");
        return false;
    }
    (void)length;
    bool valid =
        json_string(json, "listen", config->listen, sizeof(config->listen)) &&
        json_string(json, "upstream", config->upstream, sizeof(config->upstream)) &&
        json_string(json, "certificate", config->certificate, sizeof(config->certificate)) &&
        json_string(json, "privateKey", config->private_key, sizeof(config->private_key)) &&
        json_string_array_colon_list(json, "groups", config->groups, sizeof(config->groups));

    (void)json_string(json, "serverName", config->server_name, sizeof(config->server_name));
    (void)json_string(json, "caFile", config->ca_file, sizeof(config->ca_file));
    (void)json_string(json, "provider", config->provider, sizeof(config->provider));
    (void)json_string(json, "providerPath", config->provider_path, sizeof(config->provider_path));
    (void)json_string(json, "telemetryFile", config->telemetry_file, sizeof(config->telemetry_file));
    (void)json_bool(json, "verifyUpstream", &config->verify_upstream);
    free(json);

    if (!valid) {
        fprintf(stderr, "config requires listen, upstream, certificate, privateKey, and non-empty groups\n");
        return false;
    }
    if (config->groups[0] == '\0') {
        fprintf(stderr, "groups must not be empty\n");
        return false;
    }
    return true;
}

static bool split_address(const char *address, char *host, size_t host_size, char *port, size_t port_size) {
    const char *separator = strrchr(address, ':');
    if (separator == NULL || separator[1] == '\0') {
        return false;
    }
    size_t host_length = (size_t)(separator - address);
    if (host_length == 0) {
        snprintf(host, host_size, "0.0.0.0");
    } else {
        if (host_length >= host_size) {
            return false;
        }
        memcpy(host, address, host_length);
        host[host_length] = '\0';
        if (host[0] == '[' && host_length > 2 && host[host_length - 1] == ']') {
            memmove(host, host + 1, host_length - 2);
            host[host_length - 2] = '\0';
        }
    }
    if (strlen(separator + 1) >= port_size) {
        return false;
    }
    strcpy(port, separator + 1);
    return true;
}

static int create_listener(const char *address) {
    char host[256];
    char port[32];
    if (!split_address(address, host, sizeof(host), port, sizeof(port))) {
        fprintf(stderr, "invalid listen address: %s\n", address);
        return -1;
    }
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    struct addrinfo *results = NULL;
    int status = getaddrinfo(host, port, &hints, &results);
    if (status != 0) {
        fprintf(stderr, "getaddrinfo(%s): %s\n", address, gai_strerror(status));
        return -1;
    }
    int listener = -1;
    for (struct addrinfo *entry = results; entry != NULL; entry = entry->ai_next) {
        listener = socket(entry->ai_family, entry->ai_socktype, entry->ai_protocol);
        if (listener < 0) {
            continue;
        }
        int enabled = 1;
        (void)setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
        if (bind(listener, entry->ai_addr, entry->ai_addrlen) == 0 && listen(listener, 256) == 0) {
            break;
        }
        close(listener);
        listener = -1;
    }
    freeaddrinfo(results);
    return listener;
}

static int connect_upstream(const char *address) {
    char host[256];
    char port[32];
    if (!split_address(address, host, sizeof(host), port, sizeof(port))) {
        return -1;
    }
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *results = NULL;
    if (getaddrinfo(host, port, &hints, &results) != 0) {
        return -1;
    }
    int fd = -1;
    for (struct addrinfo *entry = results; entry != NULL; entry = entry->ai_next) {
        fd = socket(entry->ai_family, entry->ai_socktype, entry->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (connect(fd, entry->ai_addr, entry->ai_addrlen) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(results);
    return fd;
}

static bool set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return false;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

static bool wait_socket(int fd, short events, int timeout_ms) {
    struct pollfd descriptor = {.fd = fd, .events = events, .revents = 0};
    int result;
    do {
        result = poll(&descriptor, 1, timeout_ms);
    } while (result < 0 && errno == EINTR);
    return result > 0 && (descriptor.revents & (events | POLLERR | POLLHUP)) != 0;
}

static bool ssl_handshake(SSL *ssl, bool server) {
    int fd = SSL_get_fd(ssl);
    for (;;) {
        int result = server ? SSL_accept(ssl) : SSL_connect(ssl);
        if (result == 1) {
            return true;
        }
        int error = SSL_get_error(ssl, result);
        if (error == SSL_ERROR_WANT_READ) {
            if (!wait_socket(fd, POLLIN, 15000)) {
                return false;
            }
            continue;
        }
        if (error == SSL_ERROR_WANT_WRITE) {
            if (!wait_socket(fd, POLLOUT, 15000)) {
                return false;
            }
            continue;
        }
        return false;
    }
}

static bool ssl_write_all(SSL *ssl, const unsigned char *buffer, size_t length) {
    int fd = SSL_get_fd(ssl);
    size_t offset = 0;
    while (offset < length) {
        size_t written = 0;
        int result = SSL_write_ex(ssl, buffer + offset, length - offset, &written);
        if (result == 1) {
            offset += written;
            continue;
        }
        int error = SSL_get_error(ssl, result);
        if (error == SSL_ERROR_WANT_READ) {
            if (!wait_socket(fd, POLLIN, 15000)) {
                return false;
            }
        } else if (error == SSL_ERROR_WANT_WRITE) {
            if (!wait_socket(fd, POLLOUT, 15000)) {
                return false;
            }
        } else {
            return false;
        }
    }
    return true;
}

static int relay_read(SSL *source, SSL *destination) {
    unsigned char buffer[BUFFER_SIZE];
    size_t read_length = 0;
    int result = SSL_read_ex(source, buffer, sizeof(buffer), &read_length);
    if (result == 1) {
        if (read_length == 0) {
            return 0;
        }
        return ssl_write_all(destination, buffer, read_length) ? 1 : -1;
    }
    int error = SSL_get_error(source, result);
    if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
        return 1;
    }
    if (error == SSL_ERROR_ZERO_RETURN) {
        return 0;
    }
    return -1;
}

static void relay_bidirectional(SSL *client, SSL *upstream) {
    int client_fd = SSL_get_fd(client);
    int upstream_fd = SSL_get_fd(upstream);
    struct pollfd descriptors[2];
    descriptors[0].fd = client_fd;
    descriptors[0].events = POLLIN;
    descriptors[1].fd = upstream_fd;
    descriptors[1].events = POLLIN;
    while (!stop_requested) {
        descriptors[0].revents = 0;
        descriptors[1].revents = 0;
        int result = poll(descriptors, 2, 30000);
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result <= 0) {
            if (result == 0) {
                continue;
            }
            break;
        }
        if ((descriptors[0].revents & POLLIN) != 0 && relay_read(client, upstream) <= 0) {
            break;
        }
        if ((descriptors[1].revents & POLLIN) != 0 && relay_read(upstream, client) <= 0) {
            break;
        }
        if ((descriptors[0].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0 ||
            (descriptors[1].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            break;
        }
    }
}

static const char *group_name(SSL *ssl) {
    if (ssl == NULL) {
        return "unavailable";
    }
    const char *name = SSL_get0_group_name(ssl);
    return name == NULL || *name == '\0' ? "unknown" : name;
}

static void json_escape(FILE *file, const char *value) {
    for (const unsigned char *cursor = (const unsigned char *)value; *cursor != '\0'; cursor++) {
        switch (*cursor) {
            case '"': fputs("\\\"", file); break;
            case '\\': fputs("\\\\", file); break;
            case '\n': fputs("\\n", file); break;
            case '\r': fputs("\\r", file); break;
            case '\t': fputs("\\t", file); break;
            default:
                if (*cursor < 0x20) {
                    fprintf(file, "\\u%04x", *cursor);
                } else {
                    fputc(*cursor, file);
                }
        }
    }
}

static double elapsed_millis(const struct timespec *started) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    time_t seconds = now.tv_sec - started->tv_sec;
    long nanoseconds = now.tv_nsec - started->tv_nsec;
    return (double)seconds * 1000.0 + (double)nanoseconds / 1000000.0;
}

static bool is_pqc_group(const char *group) {
    return group != NULL && (strstr(group, "MLKEM") != NULL || strstr(group, "mlkem") != NULL || strstr(group, "ML-KEM") != NULL);
}

static void write_telemetry(struct gateway_runtime *runtime,
                            SSL *client,
                            SSL *upstream,
                            const char *status,
                            double latency_millis) {
    pthread_mutex_lock(&runtime->telemetry_lock);
    FILE *file = fopen(runtime->config.telemetry_file, "ab");
    if (file != NULL) {
        char timestamp[64];
        time_t now = time(NULL);
        struct tm utc;
        gmtime_r(&now, &utc);
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", &utc);
        const char *upstream_group = group_name(upstream);
        bool fallback = upstream != NULL && !is_pqc_group(upstream_group);
        fprintf(file, "{\"time\":\"%s\",\"status\":\"", timestamp);
        json_escape(file, status);
        fprintf(file, "\",\"latencyMillis\":%.3f,\"fallback\":%s,\"clientLeg\":{\"version\":\"",
                latency_millis,
                fallback ? "true" : "false");
        json_escape(file, client == NULL ? "unavailable" : SSL_get_version(client));
        fputs("\",\"cipher\":\"", file);
        json_escape(file, client == NULL ? "unavailable" : SSL_get_cipher_name(client));
        fputs("\",\"group\":\"", file);
        json_escape(file, group_name(client));
        fputs("\",\"pathStatus\":\"classical-or-client-dependent\"},\"upstreamLeg\":{\"version\":\"", file);
        json_escape(file, upstream == NULL ? "unavailable" : SSL_get_version(upstream));
        fputs("\",\"cipher\":\"", file);
        json_escape(file, upstream == NULL ? "unavailable" : SSL_get_cipher_name(upstream));
        fputs("\",\"group\":\"", file);
        json_escape(file, upstream_group);
        fputs("\",\"pathStatus\":\"", file);
        fputs(upstream == NULL ? "not-established" : (fallback ? "classical-fallback" : "hybrid-pqc"), file);
        fputs("\"},\"endToEndStatus\":\"partial-pqc\"}\n", file);
        fflush(file);
        fclose(file);
    }
    pthread_mutex_unlock(&runtime->telemetry_lock);
}

static void *serve_connection(void *opaque) {
    struct connection_args *args = opaque;
    struct gateway_runtime *runtime = args->runtime;
    int client_fd = args->client_fd;
    free(args);

    struct timespec started;
    clock_gettime(CLOCK_MONOTONIC, &started);
    const char *status = "client-context-failed";
    SSL *client_ssl = SSL_new(runtime->listener_ctx);
    SSL *upstream_ssl = NULL;
    int upstream_fd = -1;
    if (client_ssl == NULL) {
        close(client_fd);
        connection_release(runtime);
        return NULL;
    }
    SSL_set_fd(client_ssl, client_fd);
    set_nonblocking(client_fd);
    status = "client-handshake-failed";
    if (!ssl_handshake(client_ssl, true)) {
        openssl_error("client TLS handshake failed");
        goto cleanup;
    }

    status = "upstream-connect-failed";
    upstream_fd = connect_upstream(runtime->config.upstream);
    if (upstream_fd < 0) {
        perror("connect upstream");
        goto cleanup;
    }
    set_nonblocking(upstream_fd);
    status = "upstream-context-failed";
    upstream_ssl = SSL_new(runtime->upstream_ctx);
    if (upstream_ssl == NULL) {
        goto cleanup;
    }
    SSL_set_fd(upstream_ssl, upstream_fd);
    if (runtime->config.server_name[0] != '\0') {
        SSL_set_tlsext_host_name(upstream_ssl, runtime->config.server_name);
        SSL_set1_host(upstream_ssl, runtime->config.server_name);
    }
    status = "upstream-handshake-failed";
    if (!ssl_handshake(upstream_ssl, false)) {
        openssl_error("upstream PQC TLS handshake failed");
        goto cleanup;
    }
    status = "connected";
    relay_bidirectional(client_ssl, upstream_ssl);

cleanup:
    write_telemetry(runtime, client_ssl, upstream_ssl, status, elapsed_millis(&started));
    if (upstream_ssl != NULL) {
        SSL_shutdown(upstream_ssl);
        SSL_free(upstream_ssl);
    }
    if (upstream_fd >= 0) {
        close(upstream_fd);
    }
    SSL_shutdown(client_ssl);
    SSL_free(client_ssl);
    close(client_fd);
    connection_release(runtime);
    return NULL;
}

static bool initialize_tls(struct gateway_runtime *runtime) {
    if (runtime->config.provider_path[0] != '\0' &&
        OSSL_PROVIDER_set_default_search_path(NULL, runtime->config.provider_path) != 1) {
        openssl_error("set provider path failed");
        return false;
    }
    runtime->default_provider = OSSL_PROVIDER_load(NULL, "default");
    if (runtime->default_provider == NULL) {
        openssl_error("load default provider failed");
        return false;
    }
    if (strcmp(runtime->config.provider, "default") != 0) {
        runtime->configured_provider = OSSL_PROVIDER_load(NULL, runtime->config.provider);
        if (runtime->configured_provider == NULL) {
            openssl_error("load configured provider failed");
            return false;
        }
    }

    runtime->listener_ctx = SSL_CTX_new(TLS_server_method());
    runtime->upstream_ctx = SSL_CTX_new(TLS_client_method());
    if (runtime->listener_ctx == NULL || runtime->upstream_ctx == NULL) {
        openssl_error("create SSL context failed");
        return false;
    }
    SSL_CTX_set_min_proto_version(runtime->listener_ctx, TLS1_2_VERSION);
    SSL_CTX_set_min_proto_version(runtime->upstream_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(runtime->upstream_ctx, TLS1_3_VERSION);
    SSL_CTX_set_options(runtime->listener_ctx, SSL_OP_NO_COMPRESSION);
    SSL_CTX_set_options(runtime->upstream_ctx, SSL_OP_NO_COMPRESSION);

    if (SSL_CTX_use_certificate_chain_file(runtime->listener_ctx, runtime->config.certificate) != 1 ||
        SSL_CTX_use_PrivateKey_file(runtime->listener_ctx, runtime->config.private_key, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(runtime->listener_ctx) != 1) {
        openssl_error("load listener certificate or key failed");
        return false;
    }
    if (SSL_CTX_set1_groups_list(runtime->upstream_ctx, runtime->config.groups) != 1) {
        openssl_error("configure upstream TLS groups failed");
        return false;
    }
    if (runtime->config.verify_upstream) {
        SSL_CTX_set_verify(runtime->upstream_ctx, SSL_VERIFY_PEER, NULL);
        if (runtime->config.ca_file[0] != '\0') {
            if (SSL_CTX_load_verify_locations(runtime->upstream_ctx, runtime->config.ca_file, NULL) != 1) {
                openssl_error("load upstream CA file failed");
                return false;
            }
        } else if (SSL_CTX_set_default_verify_paths(runtime->upstream_ctx) != 1) {
            openssl_error("load system trust store failed");
            return false;
        }
    } else {
        SSL_CTX_set_verify(runtime->upstream_ctx, SSL_VERIFY_NONE, NULL);
    }
    return true;
}

static void cleanup_runtime(struct gateway_runtime *runtime) {
    if (runtime->listen_fd >= 0) {
        close(runtime->listen_fd);
        runtime->listen_fd = -1;
    }
    wait_for_connections(runtime);
    SSL_CTX_free(runtime->listener_ctx);
    SSL_CTX_free(runtime->upstream_ctx);
    OSSL_PROVIDER_unload(runtime->configured_provider);
    OSSL_PROVIDER_unload(runtime->default_provider);
    pthread_cond_destroy(&runtime->connection_drained);
    pthread_mutex_destroy(&runtime->connection_lock);
    pthread_mutex_destroy(&runtime->telemetry_lock);
}

static int run_gateway(const char *config_path, bool check_only) {
    struct gateway_runtime runtime;
    memset(&runtime, 0, sizeof(runtime));
    runtime.listen_fd = -1;
    pthread_mutex_init(&runtime.telemetry_lock, NULL);
    pthread_mutex_init(&runtime.connection_lock, NULL);
    pthread_cond_init(&runtime.connection_drained, NULL);
    if (!load_config(config_path, &runtime.config)) {
        cleanup_runtime(&runtime);
        return 2;
    }
    if (!initialize_tls(&runtime)) {
        cleanup_runtime(&runtime);
        return 3;
    }
    if (check_only) {
        printf("configuration valid: listen=%s upstream=%s groups=%s provider=%s\n",
               runtime.config.listen, runtime.config.upstream, runtime.config.groups, runtime.config.provider);
        cleanup_runtime(&runtime);
        return 0;
    }
    runtime.listen_fd = create_listener(runtime.config.listen);
    if (runtime.listen_fd < 0) {
        perror("create listener");
        cleanup_runtime(&runtime);
        return 4;
    }
    signal_listen_fd = runtime.listen_fd;
    fprintf(stderr, "PQM TLS gateway listening on %s -> %s groups=%s provider=%s\n",
            runtime.config.listen, runtime.config.upstream, runtime.config.groups, runtime.config.provider);
    while (!stop_requested) {
        int client_fd = accept(runtime.listen_fd, NULL, NULL);
        if (client_fd < 0) {
            if (stop_requested || errno == EBADF || errno == EINVAL) {
                break;
            }
            if (errno == EINTR) {
                continue;
            }
            perror("accept");
            break;
        }
        struct connection_args *args = calloc(1, sizeof(*args));
        if (args == NULL) {
            close(client_fd);
            continue;
        }
        args->runtime = &runtime;
        args->client_fd = client_fd;
        connection_acquire(&runtime);
        pthread_t thread;
        if (pthread_create(&thread, NULL, serve_connection, args) != 0) {
            connection_release(&runtime);
            close(client_fd);
            free(args);
            continue;
        }
        pthread_detach(thread);
    }
    signal_listen_fd = -1;
    cleanup_runtime(&runtime);
    return 0;
}

int main(int argc, char **argv) {
    const char *config_path = NULL;
    bool check_only = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            config_path = argv[++i];
        } else if (strcmp(argv[i], "--check-config") == 0 && i + 1 < argc) {
            config_path = argv[++i];
            check_only = true;
        } else {
            fprintf(stderr, "usage: %s --config FILE | --check-config FILE\n", argv[0]);
            return 2;
        }
    }
    if (config_path == NULL) {
        fprintf(stderr, "config path is required\n");
        return 2;
    }
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    return run_gateway(config_path, check_only);
}
