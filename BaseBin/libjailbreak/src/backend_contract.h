#ifndef LIBJAILBREAK_BACKEND_CONTRACT_H
#define LIBJAILBREAK_BACKEND_CONTRACT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "primitives_external.h"

/*
 * A handoff result only describes the control path.  It does not prove that
 * the resulting window can read or write the intended memory.  A future
 * backend must provide the independent observations below before publishing
 * any physical callback.
 */
typedef struct {
	bool handoff_succeeded;
	bool handoff_output_valid;
	bool window_read_verified;
	bool window_write_verified;
	bool resource_lifetime_verified;
	bool cleanup_verified;
	bool kernel_read_verified;
	bool kernel_write_verified;
	bool physical_read_verified;
	bool physical_write_verified;
	bool protected_memory_write_verified;
} libjailbreak_backend_attestation;

typedef struct {
	int (*kreadbuf)(uint64_t kaddr, void *output, size_t size);
	int (*kwritebuf)(uint64_t kaddr, const void *input, size_t size);
	int (*physreadbuf)(uint64_t physaddr, void *output, size_t size);
	int (*physwritebuf)(uint64_t physaddr, const void *input, size_t size);
	int (*physaccess_mapped)(uint64_t physaddr, uint64_t size, kernel_map_accessor accessorBlock);
} libjailbreak_backend_callbacks;

enum {
	LJB_BACKEND_CONTRACT_OK = 0,
	LJB_BACKEND_CONTRACT_INVALID_ARGUMENT = -1,
	LJB_BACKEND_CONTRACT_HANDOFF_UNVERIFIED = -2,
	LJB_BACKEND_CONTRACT_WINDOW_UNVERIFIED = -3,
	LJB_BACKEND_CONTRACT_LIFETIME_UNVERIFIED = -4,
	LJB_BACKEND_CONTRACT_CLEANUP_UNVERIFIED = -5,
	LJB_BACKEND_CONTRACT_CALLBACK_MISSING = -6,
	LJB_BACKEND_CONTRACT_PROTECTED_MEMORY_UNVERIFIED = -7,
};

int libjailbreak_backend_validate_attestation(
	const libjailbreak_backend_attestation *attestation,
	const libjailbreak_backend_callbacks *callbacks);

/*
 * Publish only capabilities backed by an attestation.  Validation happens
 * before gPrimitives or the capability ledger are changed; a failed call
 * therefore preserves callbacks belonging to an earlier backend.
 */
int libjailbreak_backend_publish_verified(
	const libjailbreak_backend_attestation *attestation,
	const libjailbreak_backend_callbacks *callbacks);

#endif
