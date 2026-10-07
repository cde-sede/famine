set -eu

BINS1="ls cat date head tail wc"
BINS2="env id uname seq sort uniq"

add_one() {
	dir=$1
	shift
	mkdir -p "$dir"
	for b in "$@"; do
		[ -e "$dir/$b" ] && continue
		src="/usr/bin/$b"
		if [ -x "$src" ]; then
			cp "$src" "$dir/$b"
			printf 'added %s -> %s\n' "$src" "$dir/$b"
		else
			printf 'skip: %s not found\n' "$src" >&2
			continue
		fi
		return 0
	done
	printf '%s: already full (%s)\n' "$dir" "$*"
}

add_one /tmp/test1 $BINS1
add_one /tmp/test2 $BINS2
