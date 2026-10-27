#include "backend_contract.h"

#include "primitives.h"

static bool backend_has_physical_claim(const libjailbreak_backend_attestation *attestation)
{
	return attestation->physical_read_verified ||
		attestation->physical_write_verified ||
		attestation->protected_memory_write_verified;
}

int libjailbreak_backend_validate_attestation(
	const libjailbreak_backend_attestation *attestation,
	const libjailbreak_backend_callbacks *callbacks)
{
	if (!attestation || !callbacks) return LJB_BACKEND_CONTRACT_INVALID_ARGUMENT;

	if (backend_has_physical_claim(attestation) &&
		(!attestation->handoff_succeeded || !attestation->handoff_output_valid)) {
		return LJB_BACKEND_CONTRACT_HANDOFF_UNVERIFIED;
	}

	if (attestation->physical_read_verified &&
		(!attestation->window_read_verified || !callbacks->physreadbuf)) {
		return attestation->window_read_verified
			? LJB_BACKEND_CONTRACT_CALLBACK_MISSING
			: LJB_BACKEND_CONTRACT_WINDOW_UNVERIFIED;
	}

	if (attestation->physical_write_verified &&
		(!attestation->window_write_verified || !callbacks->physwritebuf)) {
		return attestation->window_write_verified
			? LJB_BACKEND_CONTRACT_CALLBACK_MISSING
			: LJB_BACKEND_CONTRACT_WINDOW_UNVERIFIED;
	}

	if (backend_has_physical_claim(attestation) && !attestation->resource_lifetime_verified) {
		return LJB_BACKEND_CONTRACT_LIFETIME_UNVERIFIED;
	}

	if (backend_has_physical_claim(attestation) && !attestation->cleanup_verified) {
		return LJB_BACKEND_CONTRACT_CLEANUP_UNVERIFIED;
	}

	if (attestation->kernel_read_verified && !callbacks->kreadbuf) {
		return LJB_BACKEND_CONTRACT_CALLBACK_MISSING;
	}
	if (attestation->kernel_write_verified && !callbacks->kwritebuf) {
		return LJB_BACKEND_CONTRACT_CALLBACK_MISSING;
	}

	if (attestation->protected_memory_write_verified &&
		(!attestation->physical_write_verified || !attestation->window_write_verified)) {
		return LJB_BACKEND_CONTRACT_PROTECTED_MEMORY_UNVERIFIED;
	}

	return LJB_BACKEND_CONTRACT_OK;
}

int libjailbreak_backend_publish_verified(
	const libjailbreak_backend_attestation *attestation,
	const libjailbreak_backend_callbacks *callbacks)
{
	int validation = libjailbreak_backend_validate_attestation(attestation, callbacks);
	if (validation != LJB_BACKEND_CONTRACT_OK) return validation;

	/* No state is mutated before the complete contract has been accepted. */
	if (attestation->kernel_read_verified) {
		gPrimitives.kreadbuf = callbacks->kreadbuf;
		libjailbreak_capability_set(LJB_CAPABILITY_KERNEL_READ,
			LJB_CAPABILITY_RUNTIME_VERIFIED, LJB_CAPABILITY_EVIDENCE_BOUNDED_RUNTIME);
	}
	if (attestation->kernel_write_verified) {
		gPrimitives.kwritebuf = callbacks->kwritebuf;
		libjailbreak_capability_set(LJB_CAPABILITY_KERNEL_WRITE,
			LJB_CAPABILITY_RUNTIME_VERIFIED, LJB_CAPABILITY_EVIDENCE_BOUNDED_RUNTIME);
	}
	if (attestation->physical_read_verified) {
		gPrimitives.physreadbuf = callbacks->physreadbuf;
		libjailbreak_capability_set(LJB_CAPABILITY_PHYSICAL_READ,
			LJB_CAPABILITY_RUNTIME_VERIFIED, LJB_CAPABILITY_EVIDENCE_BOUNDED_RUNTIME);
	}
	if (attestation->physical_write_verified) {
		gPrimitives.physwritebuf = callbacks->physwritebuf;
		gPrimitives.physaccess_mapped = callbacks->physaccess_mapped;
		libjailbreak_capability_set(LJB_CAPABILITY_PHYSICAL_WRITE,
			LJB_CAPABILITY_RUNTIME_VERIFIED, LJB_CAPABILITY_EVIDENCE_BOUNDED_RUNTIME);
	}
	if (attestation->protected_memory_write_verified) {
		libjailbreak_capability_set(LJB_CAPABILITY_PROTECTED_MEMORY_WRITE,
			LJB_CAPABILITY_RUNTIME_VERIFIED, LJB_CAPABILITY_EVIDENCE_BOUNDED_RUNTIME);
	}

	return LJB_BACKEND_CONTRACT_OK;
}
