#ifndef CIPHER_H
#define CIPHER_H

#include <stddef.h>
#include <stdint.h>

/*
*	Freestanding: nothing here may call libc or allocate. All state lives
*	inside block_cipher_t, which the caller owns (stack or static).
*/

#define CIPHER_MAX_BLOCK	16
#define CIPHER_MAX_KEY		32
#define XOR_KEY_SIZE		16

/* SPECK-64/128: 64-bit block, 128-bit key */
#define SPECK_BLOCK_SIZE	8
#define SPECK_KEY_SIZE		16
#define SPECK_ROUNDS		27
#define SPECK_MAX_ROUNDS	32

/* TWILL, TESSERA: 64-bit block, 128-bit key nibble SPNs, see spn.h */
#define SPN_BLOCK_SIZE		8
#define SPN_KEY_SIZE		16
#define SPN_MAX_ROUNDS		32
#define TWILL_ROUNDS		16
#define TESSERA_ROUNDS		12

/* WEFT: 128-bit block, 128-bit key Feistel, see weft.c */
#define WEFT_BLOCK_SIZE		16
#define WEFT_KEY_SIZE		16
#define WEFT_ROUNDS			24
#define WEFT_MAX_ROUNDS		64

/*
*	Block cipher primitive interface
*
*	cipher_params_t is standalone so it can be built before, and apart from,
*	the cipher. A 0 field means "type default". cipher_init merges it with
*	the defaults, validates the result against the type and wires the
*	function pointers; it returns -1 for an unknown type or unsupported
*	params. setup then expands the key (params.key_size bytes) into ctx.
*
*	encrypt_block/decrypt_block process one params.block_size block;
*	dst may equal src.
*/
typedef enum cipher_type_e
{
	CIPHER_SPECK,
	CIPHER_TWILL,
	CIPHER_TESSERA,
	CIPHER_WEFT,
	CIPHER_COUNT,
}	cipher_type_t;

typedef struct cipher_params_s
{
	size_t	block_size;	/* bytes */
	size_t	key_size;	/* bytes */
	int		rounds;
}	cipher_params_t;

typedef struct speck_ctx_s
{
	uint32_t	rk[SPECK_MAX_ROUNDS];
}	speck_ctx_t;

/* round keys are derived on the fly, in both directions */
typedef struct spn_ctx_s
{
	uint64_t	start[2];	/* k[0], k[1]: the key */
	uint64_t	end[2];		/* k[R], k[R + 1]: where decryption starts */
}	spn_ctx_t;

typedef struct block_cipher_s	block_cipher_t;

struct block_cipher_s
{
	cipher_type_t	type;
	cipher_params_t	params;	/* resolved by cipher_init, no 0 left */
	union
	{
		speck_ctx_t	speck;
		spn_ctx_t	spn;
	}				ctx;
	int				(*setup)(block_cipher_t *c, const uint8_t *key);
	void			(*encrypt_block)(const block_cipher_t *c, uint8_t *dst,
						const uint8_t *src);
	void			(*decrypt_block)(const block_cipher_t *c, uint8_t *dst,
						const uint8_t *src);
};

const char		*cipher_name(cipher_type_t type);
cipher_params_t	cipher_default_params(cipher_type_t type);
int				cipher_init(block_cipher_t *c, cipher_type_t type,
					const cipher_params_t *params);

/* per-type init: validates c->params, wires the function pointers */
int				speck_init(block_cipher_t *c);
int				twill_init(block_cipher_t *c);
int				tessera_init(block_cipher_t *c);
int				weft_init(block_cipher_t *c);

/*
*	Encryption/Decryption algorithm interface
*
*	src and dst must not overlap. dst must hold at least dst_cap bytes;
*	crypt_max_size(size) is always enough, for every algo and direction.
*	On return *dst_size is the number of bytes written to dst and *status
*	is 0, or -1 on error (dst_cap too small, malformed input, bad padding,
*	no randomness). Either out pointer may be NULL.
*/
typedef enum algo_e
{
	XOR,
	ECB,
	RIPPLE,
	CTR,
	SEAL,
	ALGO_COUNT,
}	algo_t;

typedef struct xor_params_s
{
	const uint8_t	*key;	/* XOR_KEY_SIZE bytes */
}	xor_params_t;

typedef struct block_params_s
{
	const block_cipher_t	*cipher;	/* initialized and set up */
}	block_params_t;

typedef struct crypt_params_s
{
	algo_t			algo;
	uint8_t			*dst;
	size_t			dst_cap;
	size_t			*dst_size;	/* out */
	int				*status;	/* out */
	const uint8_t	*src;
	size_t			size;
	union
	{
		xor_params_t	xor_params;
		block_params_t	block_params;
	}				params;
}	crypt_params_t;

typedef void	(*t_encrypt_func)(const crypt_params_t *params);

const char		*algo_name(algo_t algo);
t_encrypt_func	get_encrypt_func(algo_t algo);
t_encrypt_func	get_decrypt_func(algo_t algo);
size_t			crypt_max_size(size_t size);

void			xor_encrypt(const crypt_params_t *params);
void			ecb_encrypt(const crypt_params_t *params);
void			ecb_decrypt(const crypt_params_t *params);
void			ripple_encrypt(const crypt_params_t *params);
void			ripple_decrypt(const crypt_params_t *params);
void			ctr_encrypt(const crypt_params_t *params);
void			ctr_decrypt(const crypt_params_t *params);
void			seal_encrypt(const crypt_params_t *params);
void			seal_decrypt(const crypt_params_t *params);

/* CTR keystream XOR, shared with SEAL; dst may equal src */
void			ctr_stream(const block_cipher_t *c, const uint8_t *nonce,
					const uint8_t *src, uint8_t *dst, size_t size);

/* raw getrandom(2) syscall, no libc; 0 or -1 */
int				random_bytes(uint8_t *dst, size_t size);

static inline void	crypt_result(const crypt_params_t *params, size_t size,
	int status)
{
	if (params->dst_size)
		*params->dst_size = size;
	if (params->status)
		*params->status = status;
}

#endif
