#ifndef SPN_H
#define SPN_H

#include <stdint.h>

#include "cipher.h"

/*
*	Shared core of TWILL and TESSERA: 64-bit nibble SPNs, 128-bit key
*
*	state = one uint64_t, 16 nibbles, nibble i at bits 4i..4i+3
*	bytes are little endian: byte 0 holds nibbles 0 and 1
*
*	encrypt
*		for i in 0 .. R - 1
*			x = L(S(x ^ k[i]))
*		x ^= k[R]
*
*	key schedule, Feistel-like, so it runs in both directions
*		k[0], k[1] = key[0..7], key[8..15]
*		k[i + 2]   = k[i] ^ F(k[i + 1]) ^ rc(i)
*		F(k)       = s ^ rotl(s, 7) ^ rotl(s, 23), s = S(k)
*		rc(i)      = RC_A ^ (i + 1) * RC_B
*	only k[0..1] and k[R..R+1] are stored; round keys are derived during
*	encryption (forward) and decryption (backward): ctx is 32 bytes.
*
*	every constant below comes from tools/design_search, seed 0x7e55e7a11;
*	tests/spn.c re-verifies the properties claimed here.
*
*	S-box  e 9 0 f 1 2 a c b 5 d 6 7 8 4 3
*		differential uniformity 4, linearity 4 (both optimal for 4 bits),
*		branch number 3, single-bit-mask linearity 2, no S(x) == x or ~x
*		evaluated bitsliced from its algebraic normal form (ANF): the 4 bit
*		planes of all 16 nibbles go through the polynomial at once, ~15 ANDs
*		and ~30 XORs per layer. No table, no data dependent shift or branch:
*		constant time, nothing to relocate. SBOX / SBOX_INV (packed lookup
*		form) are kept as the reference the tests check the ANF against.
*
*	TWILL linear layer: L(x) = x ^ rotl(x, 5) ^ rotl(x, 21) ^ rotl(x, 30)
*	                           ^ rotl(x, 36)
*		nibble branch number 6, any nibble reaches all 16 in 2 rounds.
*		In GF(2)[t] / (t^64 - 1), L = 1 + u with u^64 = 0, so
*		L^-1 = (1 + u)^63 = prod_{i < 6} (1 + u^(2^i)): the same shape with
*		every rotation multiplied by 2^i, applied for i = 0..5.
*
*	TESSERA linear layer: L = M o P on a 4x4 nibble matrix, column c is
*	16-bit lane c, row r is nibble r of the lane
*		P  nibble (c, r) moves to column c ^ r: a Latin square, every column
*		   feeds all 4 columns. Involution.
*		M  Hadamard matrix Had(6, 4, 2, 1) over GF(2^4) mod x^4 + x + 1 on
*		   each column: out[r] = sum_j h[r ^ j] in[j]. MDS (branch number 5)
*		   and involutory since 6 ^ 4 ^ 2 ^ 1 == 1.
*		L^-1 = P o M. Multiplications are SWAR xtime on all 16 nibbles.
*/

#define SPN_SBOX		0x34876d5bca21f09eULL
#define SPN_SBOX_INV	0x30a7861dcb9ef542ULL
#define SPN_ANF			0x0e9d29f710173bd2ULL
#define SPN_ANF_INV		0x4f985d9e5b470124ULL
#define SPN_RC_A		0x9d327ee8e2b9013eULL
#define SPN_RC_B		0x044d4896e0a523d5ULL
#define SPN_KS_ROT_A	7
#define SPN_KS_ROT_B	23

#define TWILL_ROT_A		5
#define TWILL_ROT_B		21
#define TWILL_ROT_C		30
#define TWILL_ROT_D		36

#define NIBBLE_ONE		0x1111111111111111ULL
#define NIBBLE_LO		0x7777777777777777ULL
#define NIBBLE_HI		0x8888888888888888ULL
#define ROW0			0x000F000F000F000FULL

/* the S and linear layers must fold against their constants to be fast */
#define SPN_INLINE		static inline __attribute__((always_inline))

SPN_INLINE uint64_t	spn_rotl(uint64_t x, unsigned n) {
	n &= 63;
	return n ? (x << n) | (x >> (64 - n)) : x;
}

static inline uint64_t	spn_load(const uint8_t *src) {
	uint64_t	v = 0;

	for (int i = 0; i < 8; ++i)
		v |= (uint64_t)src[i] << (i * 8);
	return v;
}

static inline void	spn_store(uint8_t *dst, uint64_t v) {
	for (int i = 0; i < 8; ++i)
		dst[i] = (uint8_t)(v >> (i * 8));
}

/*
*	S-box on all 16 nibbles, anf = SPN_ANF or SPN_ANF_INV
*	plane i holds bit i of every nibble (at bit 0 of the nibble); monomial v
*	is the AND of the planes in v; output bit k is the XOR of the monomials
*	set in bits 16k..16k+15 of anf. Branches only test the constant anf.
*/
/* monomial v of output bit k, kept iff anf says so: folds to m[v] or 0 */
#define SPN_TERM(m, anf, k, v)	((m)[v] & (0 - (((anf) >> (16 * (k) + (v))) & 1)))

SPN_INLINE uint64_t	spn_anf_bit(const uint64_t m[16], uint64_t anf, unsigned k) {
	return SPN_TERM(m, anf, k, 0) ^ SPN_TERM(m, anf, k, 1) ^ SPN_TERM(m, anf, k, 2)
		^ SPN_TERM(m, anf, k, 3) ^ SPN_TERM(m, anf, k, 4) ^ SPN_TERM(m, anf, k, 5)
		^ SPN_TERM(m, anf, k, 6) ^ SPN_TERM(m, anf, k, 7) ^ SPN_TERM(m, anf, k, 8)
		^ SPN_TERM(m, anf, k, 9) ^ SPN_TERM(m, anf, k, 10) ^ SPN_TERM(m, anf, k, 11)
		^ SPN_TERM(m, anf, k, 12) ^ SPN_TERM(m, anf, k, 13) ^ SPN_TERM(m, anf, k, 14)
		^ SPN_TERM(m, anf, k, 15);
}

SPN_INLINE uint64_t	spn_sub(uint64_t x, uint64_t anf) {
	uint64_t	m[16];

	m[0] = NIBBLE_ONE;
	m[1] = x & NIBBLE_ONE;
	m[2] = (x >> 1) & NIBBLE_ONE;
	m[4] = (x >> 2) & NIBBLE_ONE;
	m[8] = (x >> 3) & NIBBLE_ONE;
	m[3] = m[1] & m[2];
	m[5] = m[1] & m[4];
	m[6] = m[2] & m[4];
	m[7] = m[3] & m[4];
	m[9] = m[1] & m[8];
	m[10] = m[2] & m[8];
	m[11] = m[3] & m[8];
	m[12] = m[4] & m[8];
	m[13] = m[5] & m[8];
	m[14] = m[6] & m[8];
	m[15] = m[7] & m[8];
	return spn_anf_bit(m, anf, 0) | spn_anf_bit(m, anf, 1) << 1
		| spn_anf_bit(m, anf, 2) << 2 | spn_anf_bit(m, anf, 3) << 3;
}

SPN_INLINE uint64_t	spn_ks_f(uint64_t k) {
	uint64_t	s = spn_sub(k, SPN_ANF);

	return s ^ spn_rotl(s, SPN_KS_ROT_A) ^ spn_rotl(s, SPN_KS_ROT_B);
}

SPN_INLINE uint64_t	spn_rc(int i) {
	return SPN_RC_A ^ (uint64_t)(i + 1) * SPN_RC_B;
}

/* ------------------------------------------------------------- TWILL */

SPN_INLINE uint64_t	twill_mix(uint64_t x, unsigned scale) {
	return x ^ spn_rotl(x, TWILL_ROT_A << scale) ^ spn_rotl(x, TWILL_ROT_B << scale)
		^ spn_rotl(x, TWILL_ROT_C << scale) ^ spn_rotl(x, TWILL_ROT_D << scale);
}

SPN_INLINE uint64_t	twill_linear(uint64_t x) {
	return twill_mix(x, 0);
}

SPN_INLINE uint64_t	twill_linear_inv(uint64_t x) {
	for (unsigned i = 0; i < 6; ++i)
		x = twill_mix(x, i);
	return x;
}

/* ----------------------------------------------------------- TESSERA */

/* every nibble times x in GF(2^4), x^4 = x + 1 */
SPN_INLINE uint64_t	gf16_xtime(uint64_t x) {
	uint64_t	hi = x & NIBBLE_HI;

	return ((x & NIBBLE_LO) << 1) ^ (hi >> 3) ^ (hi >> 2);
}

/* row r <-> row r ^ 1, inside every column */
SPN_INLINE uint64_t	swap_rows1(uint64_t x) {
	return ((x & 0x0F0F0F0F0F0F0F0FULL) << 4) | ((x >> 4) & 0x0F0F0F0F0F0F0F0FULL);
}

/* row r <-> row r ^ 2, inside every column */
SPN_INLINE uint64_t	swap_rows2(uint64_t x) {
	return ((x & 0x00FF00FF00FF00FFULL) << 8) | ((x >> 8) & 0x00FF00FF00FF00FFULL);
}

/* column c <-> column c ^ 1 */
SPN_INLINE uint64_t	swap_cols1(uint64_t x) {
	return ((x & 0x0000FFFF0000FFFFULL) << 16) | ((x >> 16) & 0x0000FFFF0000FFFFULL);
}

/* out = 6x ^ 4 swap1(x) ^ 2 swap2(x) ^ swap3(x); swaps commute with GF mul */
SPN_INLINE uint64_t	tessera_mix(uint64_t x) {
	uint64_t	x2 = gf16_xtime(x);
	uint64_t	x4 = gf16_xtime(x2);

	return x4 ^ x2 ^ swap_rows1(x4) ^ swap_rows2(x2) ^ swap_rows1(swap_rows2(x));
}

/* nibble (c, r) -> (c ^ r, r) */
SPN_INLINE uint64_t	tessera_perm(uint64_t x) {
	return (x & ROW0)
		| swap_cols1(x & (ROW0 << 4))
		| spn_rotl(x & (ROW0 << 8), 32)
		| spn_rotl(swap_cols1(x & (ROW0 << 12)), 32);
}

SPN_INLINE uint64_t	tessera_linear(uint64_t x) {
	return tessera_mix(tessera_perm(x));
}

SPN_INLINE uint64_t	tessera_linear_inv(uint64_t x) {
	return tessera_perm(tessera_mix(x));
}

/* -------------------------------------------- WEFT round function, weft.c */

#define WEFT_ROT_A		5
#define WEFT_ROT_B		17

SPN_INLINE uint64_t	weft_g(uint64_t x) {
	return x ^ spn_rotl(x, WEFT_ROT_A) ^ spn_rotl(x, WEFT_ROT_B);
}

/* ------------------------------------------------------------ rounds */

int		spn_setup(block_cipher_t *c, const uint8_t *key);
int		spn_check_params(const block_cipher_t *c);

SPN_INLINE uint64_t	spn_encrypt(const block_cipher_t *c, uint64_t x,
	uint64_t (*linear)(uint64_t)) {
	uint64_t	a = c->ctx.spn.start[0];
	uint64_t	b = c->ctx.spn.start[1];

	for (int i = 0; i < c->params.rounds; ++i) {
		uint64_t	next = a ^ spn_ks_f(b) ^ spn_rc(i);

		x = linear(spn_sub(x ^ a, SPN_ANF));
		a = b;
		b = next;
	}
	return x ^ a;
}

SPN_INLINE uint64_t	spn_decrypt(const block_cipher_t *c, uint64_t x,
	uint64_t (*linear_inv)(uint64_t)) {
	uint64_t	a = c->ctx.spn.end[0];
	uint64_t	b = c->ctx.spn.end[1];

	x ^= a;
	for (int i = c->params.rounds - 1; i >= 0; --i) {
		uint64_t	prev = b ^ spn_ks_f(a) ^ spn_rc(i);

		b = a;
		a = prev;
		x = spn_sub(linear_inv(x), SPN_ANF_INV) ^ a;
	}
	return x;
}

#endif
