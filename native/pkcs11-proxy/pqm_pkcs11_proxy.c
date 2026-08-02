#define _POSIX_C_SOURCE 200809L

#include <dlfcn.h>
#include <errno.h>
#include <p11-kit/pkcs11.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static pthread_mutex_t proxy_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t audit_lock = PTHREAD_MUTEX_INITIALIZER;
static void *backend_handle = NULL;
static CK_FUNCTION_LIST_PTR backend = NULL;
static CK_FUNCTION_LIST proxy;
static bool proxy_ready = false;

struct mechanism_name {
    const char *name;
    CK_MECHANISM_TYPE value;
};

static const struct mechanism_name mechanism_names[] = {
    {"CKM_RSA_PKCS", CKM_RSA_PKCS},
    {"CKM_RSA_PKCS_PSS", CKM_RSA_PKCS_PSS},
    {"CKM_SHA1_RSA_PKCS", CKM_SHA1_RSA_PKCS},
    {"CKM_SHA256_RSA_PKCS_PSS", CKM_SHA256_RSA_PKCS_PSS},
    {"CKM_ECDSA", CKM_ECDSA},
    {"CKM_AES_ECB", CKM_AES_ECB},
    {"CKM_AES_GCM", CKM_AES_GCM},
    {"CKM_DES3_CBC", CKM_DES3_CBC},
#ifdef CKM_ML_DSA
    {"CKM_ML_DSA", CKM_ML_DSA},
#endif
#ifdef CKM_ML_KEM
    {"CKM_ML_KEM", CKM_ML_KEM},
#endif
};

static const char *mechanism_name(CK_MECHANISM_TYPE value) {
    for (size_t i = 0; i < sizeof(mechanism_names) / sizeof(mechanism_names[0]); i++) {
        if (mechanism_names[i].value == value) {
            return mechanism_names[i].name;
        }
    }
    return "UNKNOWN";
}

static bool token_contains(const char *list, const char *token) {
    if (list == NULL || *list == '\0') {
        return false;
    }
    size_t token_length = strlen(token);
    const char *cursor = list;
    while (*cursor != '\0') {
        while (*cursor == ',' || *cursor == ' ' || *cursor == '\t') {
            cursor++;
        }
        const char *end = cursor;
        while (*end != '\0' && *end != ',') {
            end++;
        }
        size_t length = (size_t)(end - cursor);
        while (length > 0 && (cursor[length - 1] == ' ' || cursor[length - 1] == '\t')) {
            length--;
        }
        if (length == token_length && strncmp(cursor, token, length) == 0) {
            return true;
        }
        cursor = end;
    }
    return false;
}

static bool mechanism_allowed(CK_MECHANISM_TYPE mechanism) {
    const char *name = mechanism_name(mechanism);
    const char *allowed = getenv("PQM_PKCS11_ALLOWED_MECHANISMS");
    if (allowed != NULL && *allowed != '\0') {
        return token_contains(allowed, name);
    }
    const char *denied = getenv("PQM_PKCS11_DENIED_MECHANISMS");
    if (denied == NULL || *denied == '\0') {
        denied = "CKM_RSA_PKCS,CKM_SHA1_RSA_PKCS,CKM_AES_ECB,CKM_DES3_CBC";
    }
    return !token_contains(denied, name);
}

static void write_audit(const char *operation, CK_SESSION_HANDLE session, CK_MECHANISM_TYPE mechanism, CK_RV result) {
    const char *path = getenv("PQM_PKCS11_AUDIT");
    if (path == NULL || *path == '\0') {
        path = "pkcs11-audit.jsonl";
    }
    pthread_mutex_lock(&audit_lock);
    FILE *file = fopen(path, "ab");
    if (file != NULL) {
        char timestamp[64];
        time_t now = time(NULL);
        struct tm utc;
        gmtime_r(&now, &utc);
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", &utc);
        fprintf(file,
                "{\"time\":\"%s\",\"operation\":\"%s\",\"session\":%lu,\"mechanism\":\"%s\",\"mechanismId\":%lu,\"result\":%lu}\n",
                timestamp,
                operation,
                (unsigned long)session,
                mechanism_name(mechanism),
                (unsigned long)mechanism,
                (unsigned long)result);
        fflush(file);
        fclose(file);
    }
    pthread_mutex_unlock(&audit_lock);
}

static CK_RV load_backend(void) {
    pthread_mutex_lock(&proxy_lock);
    if (proxy_ready) {
        pthread_mutex_unlock(&proxy_lock);
        return CKR_OK;
    }
    const char *path = getenv("PQM_PKCS11_BACKEND");
    if (path == NULL || *path == '\0') {
        pthread_mutex_unlock(&proxy_lock);
        return CKR_ARGUMENTS_BAD;
    }
    backend_handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (backend_handle == NULL) {
        pthread_mutex_unlock(&proxy_lock);
        return CKR_GENERAL_ERROR;
    }
    void *symbol = dlsym(backend_handle, "C_GetFunctionList");
    CK_C_GetFunctionList get_function_list = NULL;
    _Static_assert(sizeof(get_function_list) == sizeof(symbol), "function pointer size mismatch");
    memcpy(&get_function_list, &symbol, sizeof(get_function_list));
    if (get_function_list == NULL) {
        dlclose(backend_handle);
        backend_handle = NULL;
        pthread_mutex_unlock(&proxy_lock);
        return CKR_FUNCTION_NOT_SUPPORTED;
    }
    CK_RV result = get_function_list(&backend);
    if (result != CKR_OK || backend == NULL) {
        dlclose(backend_handle);
        backend_handle = NULL;
        backend = NULL;
        pthread_mutex_unlock(&proxy_lock);
        return result == CKR_OK ? CKR_GENERAL_ERROR : result;
    }
    memcpy(&proxy, backend, sizeof(proxy));
    proxy_ready = true;
    pthread_mutex_unlock(&proxy_lock);
    return CKR_OK;
}

CK_RV C_Initialize(CK_VOID_PTR arguments) {
    CK_RV result = load_backend();
    if (result != CKR_OK) {
        return result;
    }
    return backend->C_Initialize(arguments);
}

CK_RV C_Finalize(CK_VOID_PTR reserved) {
    pthread_mutex_lock(&proxy_lock);
    if (!proxy_ready || backend == NULL) {
        pthread_mutex_unlock(&proxy_lock);
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    CK_RV result = backend->C_Finalize(reserved);
    backend = NULL;
    proxy_ready = false;
    if (backend_handle != NULL) {
        dlclose(backend_handle);
        backend_handle = NULL;
    }
    pthread_mutex_unlock(&proxy_lock);
    return result;
}

CK_RV C_GetMechanismList(CK_SLOT_ID slot_id, CK_MECHANISM_TYPE_PTR mechanisms, CK_ULONG_PTR count) {
    CK_RV result = load_backend();
    if (result != CKR_OK) {
        return result;
    }
    CK_ULONG backend_count = 0;
    result = backend->C_GetMechanismList(slot_id, NULL, &backend_count);
    if (result != CKR_OK) {
        return result;
    }
    CK_MECHANISM_TYPE_PTR values = calloc(backend_count == 0 ? 1 : backend_count, sizeof(CK_MECHANISM_TYPE));
    if (values == NULL) {
        return CKR_HOST_MEMORY;
    }
    result = backend->C_GetMechanismList(slot_id, values, &backend_count);
    if (result != CKR_OK) {
        free(values);
        return result;
    }
    CK_ULONG filtered_count = 0;
    for (CK_ULONG i = 0; i < backend_count; i++) {
        if (mechanism_allowed(values[i])) {
            values[filtered_count++] = values[i];
        }
    }
    if (mechanisms == NULL) {
        *count = filtered_count;
        free(values);
        return CKR_OK;
    }
    if (*count < filtered_count) {
        *count = filtered_count;
        free(values);
        return CKR_BUFFER_TOO_SMALL;
    }
    memcpy(mechanisms, values, filtered_count * sizeof(CK_MECHANISM_TYPE));
    *count = filtered_count;
    free(values);
    return CKR_OK;
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slot_id, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR info) {
    CK_RV result = load_backend();
    if (result != CKR_OK) {
        return result;
    }
    if (!mechanism_allowed(type)) {
        return CKR_MECHANISM_INVALID;
    }
    return backend->C_GetMechanismInfo(slot_id, type, info);
}

CK_RV C_SignInit(CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key) {
    CK_RV result = load_backend();
    if (result != CKR_OK) {
        return result;
    }
    if (mechanism == NULL || !mechanism_allowed(mechanism->mechanism)) {
        result = CKR_MECHANISM_INVALID;
        write_audit("C_SignInit", session, mechanism == NULL ? 0 : mechanism->mechanism, result);
        return result;
    }
    result = backend->C_SignInit(session, mechanism, key);
    write_audit("C_SignInit", session, mechanism->mechanism, result);
    return result;
}

CK_RV C_Sign(CK_SESSION_HANDLE session, CK_BYTE_PTR data, CK_ULONG data_length, CK_BYTE_PTR signature, CK_ULONG_PTR signature_length) {
    CK_RV result = load_backend();
    if (result != CKR_OK) {
        return result;
    }
    result = backend->C_Sign(session, data, data_length, signature, signature_length);
    write_audit("C_Sign", session, 0, result);
    return result;
}

CK_RV C_VerifyInit(CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key) {
    CK_RV result = load_backend();
    if (result != CKR_OK) {
        return result;
    }
    if (mechanism == NULL || !mechanism_allowed(mechanism->mechanism)) {
        result = CKR_MECHANISM_INVALID;
        write_audit("C_VerifyInit", session, mechanism == NULL ? 0 : mechanism->mechanism, result);
        return result;
    }
    result = backend->C_VerifyInit(session, mechanism, key);
    write_audit("C_VerifyInit", session, mechanism->mechanism, result);
    return result;
}

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE session,
                        CK_MECHANISM_PTR mechanism,
                        CK_ATTRIBUTE_PTR public_template,
                        CK_ULONG public_count,
                        CK_ATTRIBUTE_PTR private_template,
                        CK_ULONG private_count,
                        CK_OBJECT_HANDLE_PTR public_key,
                        CK_OBJECT_HANDLE_PTR private_key) {
    CK_RV result = load_backend();
    if (result != CKR_OK) {
        return result;
    }
    if (mechanism == NULL || !mechanism_allowed(mechanism->mechanism)) {
        result = CKR_MECHANISM_INVALID;
        write_audit("C_GenerateKeyPair", session, mechanism == NULL ? 0 : mechanism->mechanism, result);
        return result;
    }
    result = backend->C_GenerateKeyPair(session, mechanism, public_template, public_count, private_template, private_count, public_key, private_key);
    write_audit("C_GenerateKeyPair", session, mechanism->mechanism, result);
    return result;
}

CK_RV C_WrapKey(CK_SESSION_HANDLE session,
                CK_MECHANISM_PTR mechanism,
                CK_OBJECT_HANDLE wrapping_key,
                CK_OBJECT_HANDLE key,
                CK_BYTE_PTR wrapped_key,
                CK_ULONG_PTR wrapped_key_length) {
    CK_RV result = load_backend();
    if (result != CKR_OK) {
        return result;
    }
    if (mechanism == NULL || !mechanism_allowed(mechanism->mechanism)) {
        result = CKR_MECHANISM_INVALID;
        write_audit("C_WrapKey", session, mechanism == NULL ? 0 : mechanism->mechanism, result);
        return result;
    }
    result = backend->C_WrapKey(session, mechanism, wrapping_key, key, wrapped_key, wrapped_key_length);
    write_audit("C_WrapKey", session, mechanism->mechanism, result);
    return result;
}

CK_RV C_UnwrapKey(CK_SESSION_HANDLE session,
                  CK_MECHANISM_PTR mechanism,
                  CK_OBJECT_HANDLE unwrapping_key,
                  CK_BYTE_PTR wrapped_key,
                  CK_ULONG wrapped_key_length,
                  CK_ATTRIBUTE_PTR attributes,
                  CK_ULONG attribute_count,
                  CK_OBJECT_HANDLE_PTR key) {
    CK_RV result = load_backend();
    if (result != CKR_OK) {
        return result;
    }
    if (mechanism == NULL || !mechanism_allowed(mechanism->mechanism)) {
        result = CKR_MECHANISM_INVALID;
        write_audit("C_UnwrapKey", session, mechanism == NULL ? 0 : mechanism->mechanism, result);
        return result;
    }
    result = backend->C_UnwrapKey(session, mechanism, unwrapping_key, wrapped_key, wrapped_key_length, attributes, attribute_count, key);
    write_audit("C_UnwrapKey", session, mechanism->mechanism, result);
    return result;
}

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR list) {
    if (list == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    CK_RV result = load_backend();
    if (result != CKR_OK) {
        return result;
    }
    proxy.C_Initialize = C_Initialize;
    proxy.C_Finalize = C_Finalize;
    proxy.C_GetFunctionList = C_GetFunctionList;
    proxy.C_GetMechanismList = C_GetMechanismList;
    proxy.C_GetMechanismInfo = C_GetMechanismInfo;
    proxy.C_SignInit = C_SignInit;
    proxy.C_Sign = C_Sign;
    proxy.C_VerifyInit = C_VerifyInit;
    proxy.C_GenerateKeyPair = C_GenerateKeyPair;
    proxy.C_WrapKey = C_WrapKey;
    proxy.C_UnwrapKey = C_UnwrapKey;
    *list = &proxy;
    return CKR_OK;
}
