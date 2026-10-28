#include "ArchiveBridge.h"

#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef struct archive archive_t;
typedef struct archive_entry archive_entry_t;

typedef archive_t *(*archive_read_new_fn)(void);
typedef int (*archive_read_support_filter_all_fn)(archive_t *);
typedef int (*archive_read_support_format_iso9660_fn)(archive_t *);
typedef int (*archive_read_open_filename_fn)(archive_t *, const char *, size_t);
typedef int (*archive_read_next_header_fn)(archive_t *, archive_entry_t **);
typedef int (*archive_read_data_skip_fn)(archive_t *);
typedef int (*archive_read_free_fn)(archive_t *);
typedef const char *(*archive_error_string_fn)(archive_t *);
typedef const char *(*archive_entry_pathname_utf8_fn)(archive_entry_t *);
typedef int64_t (*archive_entry_size_fn)(archive_entry_t *);

enum {
    ARCHIVE_OK = 0,
    ARCHIVE_EOF = 1,
    ARCHIVE_FATAL = -30
};

static void set_text(char *destination, size_t capacity, const char *value) {
    if (destination == NULL || capacity == 0) {
        return;
    }
    if (value == NULL) {
        value = "unknown";
    }
    snprintf(destination, capacity, "%s", value);
}

static void set_kind(char *kind, size_t capacity, const char *value) {
    set_text(kind, capacity, value);
}

static void set_error_message(char *message,
                              size_t capacity,
                              archive_t *archive,
                              archive_error_string_fn error_string,
                              const char *fallback) {
    const char *detail = error_string != NULL && archive != NULL
        ? error_string(archive)
        : NULL;
    set_text(message, capacity, detail != NULL && detail[0] != '\0' ? detail : fallback);
}

static void *load_symbol(void *handle, const char *name) {
    if (handle == NULL || name == NULL) {
        return NULL;
    }
    return dlsym(handle, name);
}

int32_t LAProcessISO(const char *path,
                     char *kind,
                     size_t kindCapacity,
                     char *message,
                     size_t messageCapacity,
                     uint64_t *entryCount,
                     uint64_t *totalBytes) {
    if (entryCount != NULL) {
        *entryCount = 0;
    }
    if (totalBytes != NULL) {
        *totalBytes = 0;
    }
    set_kind(kind, kindCapacity, "APP_ERROR");
    set_text(message, messageCapacity, "not started");

    if (path == NULL || path[0] == '\0') {
        set_text(message, messageCapacity, "empty input path");
        return LA_DIAGNOSTIC_ERROR;
    }

    void *handle = dlopen("/usr/lib/libarchive.2.dylib", RTLD_LAZY | RTLD_LOCAL);
    if (handle == NULL) {
        handle = dlopen("libarchive.2.dylib", RTLD_LAZY | RTLD_LOCAL);
    }
    if (handle == NULL) {
        set_kind(kind, kindCapacity, "LIBARCHIVE_UNAVAILABLE");
        set_text(message, messageCapacity, "libarchive.2.dylib could not be loaded");
        return LA_DIAGNOSTIC_UNAVAILABLE;
    }

    archive_read_new_fn read_new = (archive_read_new_fn)load_symbol(handle, "archive_read_new");
    archive_read_support_filter_all_fn support_filter_all =
        (archive_read_support_filter_all_fn)load_symbol(handle, "archive_read_support_filter_all");
    archive_read_support_format_iso9660_fn support_iso =
        (archive_read_support_format_iso9660_fn)load_symbol(handle, "archive_read_support_format_iso9660");
    archive_read_open_filename_fn open_filename =
        (archive_read_open_filename_fn)load_symbol(handle, "archive_read_open_filename");
    archive_read_next_header_fn next_header =
        (archive_read_next_header_fn)load_symbol(handle, "archive_read_next_header");
    archive_read_data_skip_fn data_skip =
        (archive_read_data_skip_fn)load_symbol(handle, "archive_read_data_skip");
    archive_read_free_fn read_free =
        (archive_read_free_fn)load_symbol(handle, "archive_read_free");
    archive_error_string_fn error_string =
        (archive_error_string_fn)load_symbol(handle, "archive_error_string");
    archive_entry_pathname_utf8_fn pathname_utf8 =
        (archive_entry_pathname_utf8_fn)load_symbol(handle, "archive_entry_pathname_utf8");
    archive_entry_size_fn entry_size =
        (archive_entry_size_fn)load_symbol(handle, "archive_entry_size");

    if (read_new == NULL || support_filter_all == NULL || support_iso == NULL ||
        open_filename == NULL || next_header == NULL || data_skip == NULL ||
        read_free == NULL || error_string == NULL || pathname_utf8 == NULL ||
        entry_size == NULL) {
        set_kind(kind, kindCapacity, "LIBARCHIVE_UNAVAILABLE");
        set_text(message, messageCapacity, "required libarchive symbols are unavailable");
        dlclose(handle);
        return LA_DIAGNOSTIC_UNAVAILABLE;
    }

    archive_t *archive = read_new();
    if (archive == NULL) {
        set_kind(kind, kindCapacity, "APP_ERROR");
        set_text(message, messageCapacity, "archive_read_new returned NULL");
        dlclose(handle);
        return LA_DIAGNOSTIC_ERROR;
    }

    int status = support_filter_all(archive);
    if (status != ARCHIVE_OK) {
        set_kind(kind, kindCapacity, "APP_ERROR");
        set_error_message(message, messageCapacity, archive, error_string,
                          "archive filter setup failed");
        read_free(archive);
        dlclose(handle);
        return LA_DIAGNOSTIC_ERROR;
    }

    status = support_iso(archive);
    if (status != ARCHIVE_OK) {
        set_kind(kind, kindCapacity, "APP_ERROR");
        set_error_message(message, messageCapacity, archive, error_string,
                          "ISO9660 format setup failed");
        read_free(archive);
        dlclose(handle);
        return LA_DIAGNOSTIC_ERROR;
    }

    status = open_filename(archive, path, 64 * 1024);
    if (status != ARCHIVE_OK) {
        set_kind(kind, kindCapacity, "ARCHIVE_REJECTED");
        set_error_message(message, messageCapacity, archive, error_string,
                          "libarchive rejected the input");
        read_free(archive);
        dlclose(handle);
        return LA_DIAGNOSTIC_REJECTED;
    }

    uint64_t entries = 0;
    uint64_t bytes = 0;
    char firstPath[160] = {0};
    archive_entry_t *entry = NULL;
    while ((status = next_header(archive, &entry)) == ARCHIVE_OK) {
        entries += 1;
        const char *entryPath = pathname_utf8(entry);
        if (entries == 1 && entryPath != NULL) {
            snprintf(firstPath, sizeof(firstPath), "%s", entryPath);
        }
        int64_t size = entry_size(entry);
        if (size > 0) {
            bytes += (uint64_t)size;
        }
        if (data_skip(archive) != ARCHIVE_OK) {
            set_kind(kind, kindCapacity, "ARCHIVE_REJECTED");
            set_error_message(message, messageCapacity, archive, error_string,
                              "archive data skip failed");
            read_free(archive);
            dlclose(handle);
            return LA_DIAGNOSTIC_REJECTED;
        }
    }

    if (entryCount != NULL) {
        *entryCount = entries;
    }
    if (totalBytes != NULL) {
        *totalBytes = bytes;
    }

    if (status != ARCHIVE_EOF) {
        set_kind(kind, kindCapacity, "ARCHIVE_REJECTED");
        set_error_message(message, messageCapacity, archive, error_string,
                          "libarchive parser returned an error");
        read_free(archive);
        dlclose(handle);
        return LA_DIAGNOSTIC_REJECTED;
    }

    set_kind(kind, kindCapacity, "ARCHIVE_PASS");
    snprintf(message, messageCapacity, "entries=%llu bytes=%llu first=%s",
             (unsigned long long)entries,
             (unsigned long long)bytes,
             firstPath[0] != '\0' ? firstPath : "none");
    read_free(archive);
    dlclose(handle);
    return LA_DIAGNOSTIC_PASS;
}
