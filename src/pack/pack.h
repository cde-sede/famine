#ifndef PACK_H
#define PACK_H

#include <stdint.h>
#include <stddef.h>

#include "cipher.h"	/* SPECK_KEY_SIZE, SPECK_BLOCK_SIZE */

/*
 * On-disk layout of a packed executable, read from the tail of the file:
 *
 *   [ loader ELF ] [ encrypted payload ] [ struct pack_trailer ]
 *
 * payload offset = file_size - sizeof(trailer) - payload_size.
 */

#define PACK_MAGIC	0x454c465041434b31ull	/* "ELFPACK1" */
#define PACK_FLAG_CAP	48

struct pack_trailer {
	uint64_t	payload_size;
	uint64_t	plain_hash;	/* FNV-1a of plaintext, detects a bad key */
	uint64_t	counter;	/* run count, bumped every run */
	uint8_t		nonce[SPECK_BLOCK_SIZE];
	uint8_t		seed[SPECK_KEY_SIZE];	/* rolling secret, rotated every run */
	char		flag[PACK_FLAG_CAP];	/* rendered marker */
	uint64_t	magic;		/* PACK_MAGIC, last 8 bytes of the file */
};

/* FNV-1a over size bytes. */
static inline uint64_t
pack_hash(const uint8_t *data, size_t size)
{
	uint64_t h = 0xcbf29ce484222325ull;
	size_t i;

	for (i = 0; i < size; ++i) {
		h ^= data[i];
		h *= 0x100000001b3ull;
	}

	return h;
}

/* Derive a 16-byte SPECK key from a string (may be empty or NULL). */
static inline void
pack_key(const char *s, uint8_t key[SPECK_KEY_SIZE])
{
	size_t i;

	for (i = 0; i < SPECK_KEY_SIZE; ++i)
		key[i] = (uint8_t)(0x5au ^ (i * 7u + 1u));

	for (i = 0; s != NULL && s[i] != '\0'; ++i) {
		unsigned j = (unsigned)(i % SPECK_KEY_SIZE);

		key[j] ^= (uint8_t)s[i];
		key[j] = (uint8_t)(key[j] * 31u + i + 1u);
	}
}

/* Per-run key: base key folded with the rolling seed (s is NULL here). */
static inline void
pack_mix(const char *s, const uint8_t seed[SPECK_KEY_SIZE],
	uint8_t key[SPECK_KEY_SIZE])
{
	size_t i;

	pack_key(s, key);

	for (i = 0; i < SPECK_KEY_SIZE; ++i)
		key[i] ^= seed[i];
}

#endif
