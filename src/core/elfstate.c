#include "elfstate.h"

#include <stdint.h>
#include <stddef.h>

#define ES_AT_PHDR  3
#define ES_AT_PHNUM 5

#define ES_SYS_READ	   0
#define ES_SYS_WRITE	  1
#define ES_SYS_CLOSE	  3
#define ES_SYS_FSTAT	  5
#define ES_SYS_PWRITE64   18
#define ES_SYS_GETPID	 39
#define ES_SYS_FSYNC	  74
#define ES_SYS_RENAME	 82
#define ES_SYS_UNLINK	 87
#define ES_SYS_READLINK   89
#define ES_SYS_FCHMOD	 91
#define ES_SYS_OPENAT	 257

#define ES_AT_FDCWD (-100)
#define ES_O_RDONLY 0
#define ES_O_WRONLY 01
#define ES_O_CREAT  0100
#define ES_O_EXCL   0200
#define ES_O_CLOEXEC 02000000

#define ES_EINTR 4

#define ES_PATH_MAX 4096
#define ES_COPY_CHUNK 4096

struct es_auxv {
	uint64_t type;
	uint64_t value;
};

/* Kernel struct stat layout on x86_64. */
struct es_stat {
	uint64_t st_dev;
	uint64_t st_ino;
	uint64_t st_nlink;
	uint32_t st_mode;
	uint32_t st_uid;
	uint32_t st_gid;
	uint32_t pad0;
	uint64_t st_rdev;
	int64_t st_size;
	int64_t st_blksize;
	int64_t st_blocks;
	uint64_t st_time[6];
	int64_t unused[3];
};

static long
es_syscall4(long n, long a, long b, long c, long d)
{
	long ret;
	register long r10 __asm__("r10") = d;

	__asm__ volatile (
		"syscall"
		: "=a"(ret)
		: "a"(n),
		  "D"(a),
		  "S"(b),
		  "d"(c),
		  "r"(r10)
		: "rcx", "r11", "memory"
	);

	return ret;
}

static long
es_sys_openat(long dirfd, const char *path, long flags, long mode)
{
	long ret;
	register long r10 __asm__("r10") = mode;

	__asm__ volatile (
		"syscall"
		: "=a"(ret)
		: "a"(ES_SYS_OPENAT),
		  "D"(dirfd),
		  "S"(path),
		  "d"(flags),
		  "r"(r10)
		: "rcx", "r11", "memory"
	);

	return ret;
}

static long
es_sys_read(long fd, void *buf, size_t count)
{
	long ret;

	__asm__ volatile (
		"syscall"
		: "=a"(ret)
		: "a"(ES_SYS_READ),
		  "D"(fd),
		  "S"(buf),
		  "d"(count)
		: "rcx", "r11", "memory"
	);

	return ret;
}

static long
es_sys_close(long fd)
{
	long ret;

	__asm__ volatile (
		"syscall"
		: "=a"(ret)
		: "a"(ES_SYS_CLOSE),
		  "D"(fd)
		: "rcx", "r11", "memory"
	);

	return ret;
}

static int
es_get_auxv(uintptr_t *phdr, size_t *phnum)
{
	struct es_auxv entry;
	long fd;

	*phdr = 0;
	*phnum = 0;

	fd = es_sys_openat(
		ES_AT_FDCWD,
		"/proc/self/auxv",
		ES_O_RDONLY,
		0
	);

	if (fd < 0)
		return -1;

	for (;;) {
		long n;

		n = es_sys_read(fd, &entry, sizeof(entry));

		if (n != (long)sizeof(entry))
			break;

		if (entry.type == 0)
			break;

		if (entry.type == ES_AT_PHDR)
			*phdr = (uintptr_t)entry.value;
		else if (entry.type == ES_AT_PHNUM)
			*phnum = (size_t)entry.value;
	}

	es_sys_close(fd);

	return (*phdr != 0 && *phnum != 0) ? 0 : -1;
}

static int
es_range_end(uintptr_t start, size_t size, uintptr_t *end)
{
	if (size == 0)
		return -1;

	if (size > UINTPTR_MAX - start)
		return -1;

	*end = start + size;
	return 0;
}

static int
es_find_load(
	const struct es_image *image,
	uintptr_t address,
	size_t size,
	const struct es_load_segment **result
)
{
	uintptr_t end;
	size_t i;

	if (es_range_end(address, size, &end) < 0)
		return -1;

	for (i = 0; i < image->load_count; ++i) {
		const struct es_load_segment *segment;

		segment = &image->load[i];

		if (address < segment->runtime_start)
			continue;

		if (end > segment->runtime_end)
			continue;

		*result = segment;
		return 0;
	}

	return -1;
}

/*
 * Linker-provided symbol at the runtime address of our own ELF header.
 * Hidden so -fpic code reaches it PC-relative, no GOT needed.
 */
extern const Elf64_Ehdr __ehdr_start __attribute__((visibility("hidden")));

/*
 * load_bias = runtime address - link-time vaddr. Zero for ET_EXEC.
 * Prefer PT_PHDR (AT_PHDR is its runtime address). Static ld output
 * often has no PT_PHDR, so fall back to the PT_LOAD mapping file
 * offset 0, which holds the ELF header.
 */
static int
es_load_bias(
	const Elf64_Phdr *phdr,
	size_t phnum,
	uintptr_t phdr_address,
	uintptr_t *bias
)
{
	size_t i;

	for (i = 0; i < phnum; ++i) {
		if (phdr[i].p_type != PT_PHDR)
			continue;

		*bias = phdr_address - (uintptr_t)phdr[i].p_vaddr;
		return 0;
	}

	for (i = 0; i < phnum; ++i) {
		if (phdr[i].p_type != PT_LOAD || phdr[i].p_offset != 0)
			continue;

		*bias = (uintptr_t)&__ehdr_start - (uintptr_t)phdr[i].p_vaddr;
		return 0;
	}

	return -1;
}

void
es_image_reset(struct es_image *image)
{
	unsigned char *p;
	size_t n;

	if (image == NULL)
		return;

	p = (unsigned char *)image;
	n = sizeof(*image);

	while (n--)
		*p++ = 0;
}

int
es_init(struct es_image *image)
{
	uintptr_t phdr_address;
	size_t phnum;
	uintptr_t load_bias;
	const Elf64_Phdr *phdr;
	size_t i;

	if (image == NULL)
		return -1;

	es_image_reset(image);

	if (es_get_auxv(&phdr_address, &phnum) < 0)
		return -1;

	if (phnum > ES_MAX_LOAD_SEGMENTS * 4)
		return -1;

	phdr = (const Elf64_Phdr *)phdr_address;

	if (es_load_bias(phdr, phnum, phdr_address, &load_bias) < 0)
		return -1;

	image->load_bias = load_bias;
	image->phdr = phdr;
	image->phnum = phnum;

	for (i = 0; i < phnum; ++i) {
		const Elf64_Phdr *p = &phdr[i];
		struct es_load_segment *segment;
		uintptr_t runtime_start;
		uintptr_t runtime_end;

		if (p->p_type != PT_LOAD)
			continue;

		if (p->p_memsz < p->p_filesz)
			return -1;

		if (image->load_count >= ES_MAX_LOAD_SEGMENTS)
			return -1;

		if (p->p_vaddr > UINTPTR_MAX - p->p_memsz)
			return -1;

		if (load_bias > UINTPTR_MAX - p->p_vaddr)
			return -1;

		runtime_start =
			load_bias + (uintptr_t)p->p_vaddr;

		runtime_end =
			runtime_start + (uintptr_t)p->p_memsz;

		segment = &image->load[image->load_count++];

		segment->runtime_start = runtime_start;
		segment->runtime_end = runtime_end;
		segment->vaddr = p->p_vaddr;
		segment->file_offset = p->p_offset;
		segment->filesz = p->p_filesz;
		segment->memsz = p->p_memsz;
		segment->flags = p->p_flags;
	}

	return image->load_count != 0 ? 0 : -1;
}

int
es_runtime_to_file(
	const struct es_image *image,
	uintptr_t address,
	size_t size,
	Elf64_Off *file_offset
)
{
	const struct es_load_segment *segment;
	uintptr_t relative;

	if (image == NULL || file_offset == NULL)
		return -1;

	if (es_find_load(
			image,
			address,
			size,
			&segment) < 0)
		return -1;

	relative = address - segment->runtime_start;

	if (relative >= segment->filesz)
		return -2;

	if (size > segment->filesz - relative)
		return -2;

	if (segment->file_offset >
		UINT64_MAX - relative)
		return -3;

	*file_offset =
		segment->file_offset + relative;

	return 0;
}

int
es_register_runtime(
	struct es_image *image,
	void *address,
	size_t size,
	struct es_region **out
)
{
	Elf64_Off offset;
	struct es_region *region;

	if (image == NULL || address == NULL || size == 0)
		return -1;

	if (image->region_count >= ES_MAX_REGIONS)
		return -1;

	if (es_runtime_to_file(
			image,
			(uintptr_t)address,
			size,
			&offset) < 0)
		return -1;

	region = &image->regions[image->region_count++];

	region->runtime_address = (uintptr_t)address;
	region->file_offset = offset;
	region->size = size;
	region->flags =
		ES_REGION_RUNTIME |
		ES_REGION_FILE_BACKED;
	region->staged = NULL;

	if (out != NULL)
		*out = region;

	return 0;
}

int
es_register_file(
	struct es_image *image,
	Elf64_Off offset,
	size_t size,
	struct es_region **out
)
{
	struct es_region *region;

	if (image == NULL || size == 0)
		return -1;

	if (image->region_count >= ES_MAX_REGIONS)
		return -1;

	if ((uint64_t)size >
		UINT64_MAX - (uint64_t)offset)
		return -1;

	region = &image->regions[image->region_count++];

	region->runtime_address = 0;
	region->file_offset = offset;
	region->size = size;
	region->flags =
		ES_REGION_FILE |
		ES_REGION_FILE_BACKED;
	region->staged = NULL;

	if (out != NULL)
		*out = region;

	return 0;
}

int
es_region_read_runtime(
	const struct es_region *region,
	void *dst,
	size_t size
)
{
	const unsigned char *src;
	unsigned char *out;
	size_t i;

	if (region == NULL || dst == NULL)
		return -1;

	if (!(region->flags & ES_REGION_RUNTIME))
		return -1;

	if (size > region->size)
		return -1;

	src = (const unsigned char *)region->runtime_address;
	out = (unsigned char *)dst;

	for (i = 0; i < size; ++i)
		out[i] = src[i];

	return 0;
}

/*
 * Writing layer.
 *
 * A running executable can't be opened for writing (ETXTBSY), so a
 * commit rebuilds our own file: copy /proc/self/exe to "<path>.es-<pid>"
 * in the same directory, patch every region into it, fsync, then
 * rename() it over <path>. The rename is atomic, and the process keeps
 * running from the old inode it already has mapped.
 */

static int
es_write_all(long fd, const void *buf, size_t size)
{
	const unsigned char *p = (const unsigned char *)buf;

	while (size > 0) {
		long n;

		n = es_syscall4(ES_SYS_WRITE, fd, (long)p, (long)size, 0);

		if (n == -ES_EINTR)
			continue;

		if (n <= 0)
			return -1;

		p += n;
		size -= (size_t)n;
	}

	return 0;
}

static int
es_pwrite_all(long fd, const void *buf, size_t size, Elf64_Off offset)
{
	const unsigned char *p = (const unsigned char *)buf;

	while (size > 0) {
		long n;

		n = es_syscall4(
			ES_SYS_PWRITE64,
			fd,
			(long)p,
			(long)size,
			(long)offset
		);

		if (n == -ES_EINTR)
			continue;

		if (n <= 0)
			return -1;

		p += n;
		size -= (size_t)n;
		offset += (Elf64_Off)n;
	}

	return 0;
}

/* Copy src to dst until EOF. */
static int
es_copy_fd(long src, long dst)
{
	unsigned char buf[ES_COPY_CHUNK];

	for (;;) {
		long n;

		n = es_sys_read(src, buf, sizeof(buf));

		if (n == -ES_EINTR)
			continue;

		if (n < 0)
			return -1;

		if (n == 0)
			return 0;

		if (es_write_all(dst, buf, (size_t)n) < 0)
			return -1;
	}
}

/* Resolve our own path. Fails if the file was deleted or replaced. */
static int
es_self_path(char *path, size_t cap, size_t *len)
{
	static const char deleted[] = " (deleted)";
	const size_t dlen = sizeof(deleted) - 1;
	long n;
	size_t i;

	n = es_syscall4(
		ES_SYS_READLINK,
		(long)"/proc/self/exe",
		(long)path,
		(long)(cap - 1),
		0
	);

	if (n <= 0 || (size_t)n >= cap - 1)
		return -1;

	path[n] = '\0';

	if ((size_t)n > dlen) {
		for (i = 0; i < dlen; ++i)
			if (path[(size_t)n - dlen + i] != deleted[i])
				break;

		if (i == dlen)
			return -1;
	}

	*len = (size_t)n;
	return 0;
}

/* Append ".es-<pid>" to path, in place. */
static int
es_tmp_path(char *path, size_t len, size_t cap)
{
	static const char suffix[] = ".es-";
	char digits[20];
	size_t ndigits = 0;
	unsigned long pid;
	size_t i;

	pid = (unsigned long)es_syscall4(ES_SYS_GETPID, 0, 0, 0, 0);

	do {
		digits[ndigits++] = (char)('0' + pid % 10);
		pid /= 10;
	} while (pid != 0);

	if (len + sizeof(suffix) - 1 + ndigits + 1 > cap)
		return -1;

	for (i = 0; i < sizeof(suffix) - 1; ++i)
		path[len++] = suffix[i];

	while (ndigits > 0)
		path[len++] = digits[--ndigits];

	path[len] = '\0';
	return 0;
}

static int
es_region_source(const struct es_region *region, const void **src)
{
	if (region->flags & ES_REGION_RUNTIME) {
		*src = (const void *)region->runtime_address;
		return 0;
	}

	if (region->flags & ES_REGION_STAGED) {
		*src = region->staged;
		return 0;
	}

	return -1;
}

int
es_region_stage(struct es_region *region, const void *src)
{
	if (region == NULL || src == NULL)
		return -1;

	if (!(region->flags & ES_REGION_FILE))
		return -1;

	region->staged = src;
	region->flags |= ES_REGION_STAGED;

	return 0;
}

/*
 * Shared emitter. Copy base_path (NULL = /proc/self/exe) to a temp file
 * beside dst_path, write every staged/runtime region at its file_offset,
 * then rename over dst_path. When allow_grow is 0 regions must fit inside
 * the base; when 1 they may extend past it (pwrite grows the file), which
 * is how a new file is assembled from a base plus appended regions.
 */
static int
es_emit(
	const struct es_image *image,
	const char *base_path,
	const char *dst_path,
	int allow_grow
)
{
	char path[ES_PATH_MAX];
	char tmp[ES_PATH_MAX];
	struct es_stat st;
	size_t len;
	size_t i;
	long src;
	long dst;

	if (image == NULL || dst_path == NULL)
		return -1;

	if (base_path == NULL)
		base_path = "/proc/self/exe";

	/* Copy dst_path into our own buffer, then derive the temp name. */
	for (len = 0; dst_path[len] != '\0'; ++len) {
		if (len >= ES_PATH_MAX - 1)
			return -1;
		path[len] = dst_path[len];
	}
	path[len] = '\0';

	for (i = 0; i <= len; ++i)
		tmp[i] = path[i];

	if (es_tmp_path(tmp, len, sizeof(tmp)) < 0)
		return -1;

	src = es_sys_openat(ES_AT_FDCWD, base_path, ES_O_RDONLY | ES_O_CLOEXEC, 0);

	if (src < 0)
		return -1;

	if (es_syscall4(ES_SYS_FSTAT, src, (long)&st, 0, 0) < 0) {
		es_sys_close(src);
		return -1;
	}

	/* Without grow, every region must lie inside the base file. */
	if (!allow_grow) {
		for (i = 0; i < image->region_count; ++i) {
			const struct es_region *region = &image->regions[i];

			if (region->file_offset > (uint64_t)st.st_size ||
				region->size >
					(uint64_t)st.st_size - region->file_offset) {
				es_sys_close(src);
				return -1;
			}
		}
	}

	dst = es_sys_openat(
		ES_AT_FDCWD,
		tmp,
		ES_O_WRONLY | ES_O_CREAT | ES_O_EXCL | ES_O_CLOEXEC,
		0700
	);

	if (dst < 0) {
		es_sys_close(src);
		return -1;
	}

	if (es_copy_fd(src, dst) < 0)
		goto fail;

	for (i = 0; i < image->region_count; ++i) {
		const struct es_region *region = &image->regions[i];
		const void *data;

		/* File regions never staged keep their current bytes. */
		if (es_region_source(region, &data) < 0)
			continue;

		if (es_pwrite_all(
				dst,
				data,
				region->size,
				region->file_offset) < 0)
			goto fail;
	}

	/* Keep the base's permission bits; open() mode is masked by umask. */
	if (es_syscall4(ES_SYS_FCHMOD, dst, st.st_mode & 07777, 0, 0) < 0)
		goto fail;

	if (es_syscall4(ES_SYS_FSYNC, dst, 0, 0, 0) < 0)
		goto fail;

	es_sys_close(src);

	if (es_sys_close(dst) < 0) {
		es_syscall4(ES_SYS_UNLINK, (long)tmp, 0, 0, 0);
		return -1;
	}

	if (es_syscall4(ES_SYS_RENAME, (long)tmp, (long)path, 0, 0) < 0) {
		es_syscall4(ES_SYS_UNLINK, (long)tmp, 0, 0, 0);
		return -1;
	}

	return 0;

fail:
	es_sys_close(src);
	es_sys_close(dst);
	es_syscall4(ES_SYS_UNLINK, (long)tmp, 0, 0, 0);
	return -1;
}

int
es_commit_to(const struct es_image *image, const char *dst_path)
{
	return es_emit(image, NULL, dst_path, 0);
}

int
es_build_to(
	const struct es_image *image,
	const char *base_path,
	const char *dst_path
)
{
	return es_emit(image, base_path, dst_path, 1);
}

int
es_commit(const struct es_image *image)
{
	char path[ES_PATH_MAX];
	size_t len;

	if (image == NULL)
		return -1;

	if (es_self_path(path, sizeof(path), &len) < 0)
		return -1;

	return es_commit_to(image, path);
}
