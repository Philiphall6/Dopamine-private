#ifndef ARCHIVE_BRIDGE_H
#define ARCHIVE_BRIDGE_H

#include <stdint.h>
#include <stddef.h>

enum LADiagnosticKind {
    LA_DIAGNOSTIC_PASS = 0,
    LA_DIAGNOSTIC_REJECTED = 1,
    LA_DIAGNOSTIC_UNAVAILABLE = 2,
    LA_DIAGNOSTIC_ERROR = 3
};

int32_t LAProcessISO(const char *path,
                     char *kind,
                     size_t kindCapacity,
                     char *message,
                     size_t messageCapacity,
                     uint64_t *entryCount,
                     uint64_t *totalBytes);

#endif
