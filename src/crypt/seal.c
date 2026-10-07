/*
*	SEAL: authenticated encryption, CTR then a MAC over nonce and ciphertext
*	(encrypt-then-MAC)
*
*	bs = cipher block size, K = the cipher's key
*
*	subkeys, so CTR and MAC never share a key
*		Kenc = EncryptBlock_K(D(0, 'E')) | EncryptBlock_K(D(1, 'E')) | ...
*		Kmac = same with 'M'
*		D(i, d) = block of zeros, byte 0 = i, byte 1 = d
*		(truncated to the key size)
*
*	encrypt
*		N = random bs bytes
*		C = CTR_Kenc(N, P)
*		T = MAC_Kmac(N, C)
*		output N | C | T, exactly 2 * bs bytes longer than P
*
*	MAC: CBC-MAC with the length first, which makes it safe for messages of
*	any length (no message is a prefix of another)
*		S = 0
*		for each block B of  LEN | N | C | zero padding to bs
*			S = EncryptBlock_Kmac(S ^ B)
*		T = S
*		LEN = len(C) as little endian 64-bit, zero padded to bs
*
*	decrypt: recompute T over the received N | C, compare in constant time,
*	and only then decrypt. Any modification fails (status -1) and nothing is
*	written to dst. Forgery odds per attempt ~2^-(8 * bs).
*
*	no heap: the two subkeyed ciphers live on the stack (2 block_cipher_t)
* */

#include <stdint.h>

#include "cipher.h"

static void	derive_key(const block_cipher_t *c, uint8_t domain, uint8_t *key) {
	size_t	bs = c->params.block_size;
	size_t	ks = c->params.key_size;
	uint8_t	in[CIPHER_MAX_BLOCK];
	uint8_t	out[CIPHER_MAX_BLOCK];

	for (size_t off = 0; off < ks; off += bs) {
		for (size_t i = 0; i < bs; ++i)
			in[i] = 0;
		in[0] = (uint8_t)(off / bs);
		in[1] = domain;
		c->encrypt_block(c, out, in);
		for (size_t i = 0; i < bs && off + i < ks; ++i)
			key[off + i] = out[i];
	}
}

static void	wipe(void *p, size_t size) {
	volatile uint8_t	*v = p;

	while (size--)
		*v++ = 0;
}

static int	seal_keys(const block_cipher_t *c, block_cipher_t *enc, block_cipher_t *mac) {
	uint8_t	key[CIPHER_MAX_KEY];
	int		status = 0;

	if (cipher_init(enc, c->type, &c->params) != 0
		|| cipher_init(mac, c->type, &c->params) != 0)
		return -1;
	derive_key(c, 'E', key);
	status |= enc->setup(enc, key);
	derive_key(c, 'M', key);
	status |= mac->setup(mac, key);
	wipe(key, sizeof(key));
	return status;
}

/* absorbs size bytes into the CBC state, the last block zero padded */
static void	mac_absorb(const block_cipher_t *mac, uint8_t *state,
	const uint8_t *data, size_t size) {
	size_t	bs = mac->params.block_size;

	for (size_t off = 0; off < size; off += bs) {
		for (size_t i = 0; i < bs; ++i)
			state[i] ^= off + i < size ? data[off + i] : 0;
		mac->encrypt_block(mac, state, state);
	}
}

static void	mac_compute(const block_cipher_t *mac, const uint8_t *nonce,
	const uint8_t *data, size_t size, uint8_t *tag) {
	size_t	bs = mac->params.block_size;
	uint8_t	len[CIPHER_MAX_BLOCK];

	for (size_t i = 0; i < bs; ++i) {
		tag[i] = 0;
		len[i] = i < 8 ? (uint8_t)((uint64_t)size >> (8 * i)) : 0;
	}
	mac_absorb(mac, tag, len, bs);
	mac_absorb(mac, tag, nonce, bs);
	mac_absorb(mac, tag, data, size);
}

void	seal_encrypt(const crypt_params_t *params) {
	const block_cipher_t	*c = params->params.block_params.cipher;
	size_t					bs = c->params.block_size;
	size_t					n = params->size;
	block_cipher_t			enc;
	block_cipher_t			mac;

	if (n > SIZE_MAX - 2 * bs || 2 * bs + n > params->dst_cap
		|| seal_keys(c, &enc, &mac) != 0
		|| random_bytes(params->dst, bs) != 0) {
		crypt_result(params, 0, -1);
		return;
	}
	ctr_stream(&enc, params->dst, params->src, params->dst + bs, n);
	mac_compute(&mac, params->dst, params->dst + bs, n, params->dst + bs + n);
	wipe(&enc.ctx, sizeof(enc.ctx));
	wipe(&mac.ctx, sizeof(mac.ctx));
	crypt_result(params, 2 * bs + n, 0);
}

void	seal_decrypt(const crypt_params_t *params) {
	const block_cipher_t	*c = params->params.block_params.cipher;
	size_t					bs = c->params.block_size;
	block_cipher_t			enc;
	block_cipher_t			mac;
	uint8_t					tag[CIPHER_MAX_BLOCK];
	uint8_t					diff = 0;
	size_t					n;

	if (params->size < 2 * bs || params->size - 2 * bs > params->dst_cap
		|| seal_keys(c, &enc, &mac) != 0) {
		crypt_result(params, 0, -1);
		return;
	}
	n = params->size - 2 * bs;
	mac_compute(&mac, params->src, params->src + bs, n, tag);
	for (size_t i = 0; i < bs; ++i)
		diff |= tag[i] ^ params->src[bs + n + i];
	if (diff == 0)
		ctr_stream(&enc, params->src, params->src + bs, params->dst, n);
	wipe(&enc.ctx, sizeof(enc.ctx));
	wipe(&mac.ctx, sizeof(mac.ctx));
	crypt_result(params, diff == 0 ? n : 0, diff == 0 ? 0 : -1);
}
