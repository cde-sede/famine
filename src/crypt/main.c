/*
*	Encryption/Decryption algorithm interface convention: see cipher.h
*/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cipher.h"

static int usage(const char *name) {
	fprintf(stderr, "usage: %s -e | -d [-r rounds] [-k hexkey] [algo] [cipher]\n", name);
	fprintf(stderr, "  algo:  ");
	for (int a = 0; a < ALGO_COUNT; ++a)
		fprintf(stderr, " %s", algo_name((algo_t)a));
	fprintf(stderr, " (default ecb)\n  cipher:");
	for (int t = 0; t < CIPHER_COUNT; ++t)
		fprintf(stderr, " %s", cipher_name((cipher_type_t)t));
	fprintf(stderr, " (default speck)\n"
		"  -r rounds  cipher round count (default: the cipher's own)\n"
		"  -k hexkey  key in hex, up to the cipher's key size (xor: %d bytes),\n"
		"             shorter keys are zero padded on the left;\n"
		"             default is a built-in demo key\n", XOR_KEY_SIZE);
	return 1;
}

static int	find_algo(const char *name) {
	for (int a = 0; a < ALGO_COUNT; ++a)
		if (strcmp(algo_name((algo_t)a), name) == 0)
			return a;
	return -1;
}

static int	find_cipher(const char *name) {
	for (int t = 0; t < CIPHER_COUNT; ++t)
		if (strcmp(cipher_name((cipher_type_t)t), name) == 0)
			return t;
	return -1;
}

/*
*	up to size bytes of hex, read as a number: a shorter string is padded with
*	zeros on the left ("1234" -> 00 .. 00 12 34), odd lengths are fine
*/
static int	parse_hex(const char *hex, uint8_t *dst, size_t size) {
	size_t	len = strlen(hex);
	size_t	pad;

	if (len == 0 || len > size * 2)
		return -1;
	pad = size * 2 - len;
	for (size_t i = 0; i < size * 2; ++i) {
		char	ch = i < pad ? '0' : hex[i - pad];
		int		v;

		if (ch >= '0' && ch <= '9')
			v = ch - '0';
		else if (ch >= 'a' && ch <= 'f')
			v = ch - 'a' + 10;
		else if (ch >= 'A' && ch <= 'F')
			v = ch - 'A' + 10;
		else
			return -1;
		if (i % 2 == 0)
			dst[i / 2] = (uint8_t)(v << 4);
		else
			dst[i / 2] |= (uint8_t)v;
	}
	return 0;
}

/* reads all of stdin into a malloc'd buffer, NULL on error */
static uint8_t *read_all(FILE *f, size_t *size) {
	size_t cap = 4096;
	size_t len = 0;
	uint8_t *buf = malloc(cap);
	size_t n;

	if (!buf)
		return NULL;
	while ((n = fread(buf + len, 1, cap - len, f)) > 0) {
		len += n;
		if (len == cap) {
			uint8_t *tmp = realloc(buf, cap * 2);
			if (!tmp) {
				free(buf);
				return NULL;
			}
			buf = tmp;
			cap *= 2;
		}
	}
	if (ferror(f)) {
		free(buf);
		return NULL;
	}
	*size = len;
	return buf;
}

int	main(int ac, char **av) {
	const uint32_t key_words[4] = {0xDEADBEEF, 0xCAFEBABE, 0x8BADF00D, 0xFEEDFACE};
	uint8_t key[CIPHER_MAX_KEY] = {0};
	block_cipher_t cipher;
	cipher_params_t cparams = {0};
	cipher_type_t type = CIPHER_SPECK;
	algo_t algo = ECB;
	const char *hexkey = NULL;
	int decrypt = -1;
	t_encrypt_func func;

	for (int i = 1; i < ac; ++i) {
		int	found;

		if (strcmp(av[i], "-e") == 0 || strcmp(av[i], "-d") == 0)
			decrypt = av[i][1] == 'd';
		else if (strcmp(av[i], "-r") == 0 && i + 1 < ac) {
			cparams.rounds = atoi(av[++i]);
			if (cparams.rounds <= 0)
				return usage(av[0]);
		}
		else if (strcmp(av[i], "-k") == 0 && i + 1 < ac)
			hexkey = av[++i];
		else if ((found = find_algo(av[i])) >= 0)
			algo = (algo_t)found;
		else if ((found = find_cipher(av[i])) >= 0)
			type = (cipher_type_t)found;
		else
			return usage(av[0]);
	}
	if (decrypt < 0)
		return usage(av[0]);
	func = decrypt ? get_decrypt_func(algo) : get_encrypt_func(algo);

	if (cipher_init(&cipher, type, &cparams) != 0) {
		fprintf(stderr, "%s: %s does not support these params\n", av[0], cipher_name(type));
		return 1;
	}
	if (hexkey) {
		size_t need = algo == XOR ? XOR_KEY_SIZE : cipher.params.key_size;

		if (parse_hex(hexkey, key, need) != 0) {
			fprintf(stderr, "%s: key must be 1 to %zu bytes of hex\n", av[0], need);
			return 1;
		}
	}
	else
		for (int i = 0; i < 16; ++i)
			key[i] = (uint8_t)(key_words[i / 4] >> (i % 4 * 8));
	if (cipher.setup(&cipher, key) != 0) {
		fprintf(stderr, "%s: cipher setup failed\n", av[0]);
		return 1;
	}

	size_t size;
	uint8_t *src = read_all(stdin, &size);
	if (!src) {
		perror(av[0]);
		return 1;
	}
	size_t cap = crypt_max_size(size);
	uint8_t *dst = malloc(cap);
	if (!dst) {
		perror(av[0]);
		free(src);
		return 1;
	}

	size_t dst_size = 0;
	int status = -1;
	crypt_params_t params = {
		.algo = algo,
		.dst = dst,
		.dst_cap = cap,
		.dst_size = &dst_size,
		.status = &status,
		.src = src,
		.size = size,
	};
	if (algo == XOR)
		params.params.xor_params.key = key;
	else
		params.params.block_params.cipher = &cipher;
	func(&params);

	if (status != 0)
		fprintf(stderr, "%s: %s failed\n", av[0], decrypt ? "decryption" : "encryption");
	else
		fwrite(dst, 1, dst_size, stdout);
	free(src);
	free(dst);
	return status != 0;
}
