/* FidoManager tests only: compiled with exact functions extracted from pinned source. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <cbor.h>

#define _FIDO_INTERNAL
#include "fido/credman.h"

static unsigned allocator_calls;

static void *
instrumented_recallocarray(void *old, size_t old_count, size_t n, size_t size)
{
	(void)old_count;
	assert(old == NULL);
	allocator_calls++;
	/* Record but never actually attempt an over-limit allocation, even in the
	 * unpatched negative control. Under-limit allocations use the real entry size. */
	if (n > FIDOMANAGER_TEST_LIMIT)
		return NULL;
	return calloc(n == 0 ? 1 : n, size);
}

#define recallocarray instrumented_recallocarray
#define fido_log_debug(...) ((void)0)
#include "reviewed-parser.inc"

static void
check_count(uint64_t n, bool rp_path)
{
	fido_credman_rp_t rp = {0};
	fido_credman_rk_t rk = {0};
	cbor_item_t *key = cbor_build_uint8(rp_path ? 5 : 9);
	cbor_item_t *value = cbor_build_uint64(n);
	assert(key != NULL && value != NULL);
	allocator_calls = 0;
	int result = rp_path ? credman_parse_rp_count(key, value, &rp) :
	    credman_parse_rk_count(key, value, &rk);
	if (n <= FIDOMANAGER_TEST_LIMIT) {
		assert(result == 0);
		assert(allocator_calls == 1);
		assert((rp_path ? rp.n_alloc : rk.n_alloc) == n);
		assert((rp_path ? rp.n_rx : rk.n_rx) == 0);
	} else {
		assert(result == -1);
#ifdef EXPECT_UNPATCHED
		assert(allocator_calls == 1); /* negative control proves instrumentation */
#else
		assert(allocator_calls == 0); /* the required pre-allocation guarantee */
#endif
		assert(rp.ptr == NULL && rk.ptr == NULL);
		assert(rp.n_alloc == 0 && rk.n_alloc == 0);
	}
	free(rp.ptr);
	free(rk.ptr);
	cbor_decref(&key);
	cbor_decref(&value);
}

static void
check_original_sanity_checks(void)
{
	/* An array with received entries cannot grow. Its state must stay unchanged. */
	uint8_t buffer[8] = {0};
	void *pointer = buffer;
	size_t allocated = 1, received = 1;
	allocator_calls = 0;
	assert(credman_grow_array(&pointer, &allocated, &received, 2, 1) == -1);
	assert(pointer == buffer && allocated == 1 && received == 1);
	assert(allocator_calls == 0);
	/* A smaller count retains the existing upstream no-growth behavior. */
	assert(credman_grow_array(&pointer, &allocated, &received, 0, 1) == 0);
	assert(pointer == buffer && allocated == 1 && allocator_calls == 0);
	/* Both parsers still reject a non-unsigned count before allocation. */
	cbor_item_t *value = cbor_build_bool(true);
	cbor_item_t *rp_key = cbor_build_uint8(5), *rk_key = cbor_build_uint8(9);
	fido_credman_rp_t rp = {0};
	fido_credman_rk_t rk = {0};
	assert(value != NULL && rp_key != NULL && rk_key != NULL);
	assert(credman_parse_rp_count(rp_key, value, &rp) == -1);
	assert(credman_parse_rk_count(rk_key, value, &rk) == -1);
	assert(allocator_calls == 0);
	cbor_decref(&value);
	cbor_decref(&rp_key);
	cbor_decref(&rk_key);
}

int
main(void)
{
	const uint64_t counts[] = {0, 1, FIDOMANAGER_TEST_LIMIT - 1,
	    FIDOMANAGER_TEST_LIMIT, FIDOMANAGER_TEST_LIMIT + 1,
	    UINT64_C(1000000000), UINT32_MAX, UINT64_MAX};
#ifndef EXPECT_UNPATCHED
	assert(FIDOMANAGER_CREDMAN_MAX_ENTRIES == FIDOMANAGER_TEST_LIMIT);
	assert(fidomanager_libfido2_1_17_0_credman_limit() == FIDOMANAGER_TEST_LIMIT);
#endif
	for (size_t i = 0; i < sizeof(counts) / sizeof(counts[0]); i++) {
		check_count(counts[i], true);
		check_count(counts[i], false);
	}
	check_original_sanity_checks();
#ifdef EXPECT_UNPATCHED
	puts("PASS: unpatched RP/RK negative control reaches refusing allocator for oversized counts");
#else
	puts("PASS: patched RP/RK boundary tests; every oversized count rejected before allocator");
#endif
	return 0;
}
