# Isolated dev/build environment for elfstate.
#
# Just the toolchain the Makefile and test.sh need: gcc, make, ld/strings
# (binutils), gdb, and the coreutils used by the tests (stat, tail, strings).
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        make \
        binutils \
        libc6-dev \
        gdb \
        file \
        zsh \
        git \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# oh-my-zsh in a non-mounted home (compose bind-mounts the source over /work,
# so HOME lives at /home/dev instead). A baked .zshrc also skips zsh's
# interactive first-run config (zsh-newuser-install). Owned by uid 1000 to
# match the host user compose runs as.
RUN git clone --depth=1 https://github.com/ohmyzsh/ohmyzsh.git /home/dev/.oh-my-zsh \
    && printf '%s\n' \
        'export ZSH="/home/dev/.oh-my-zsh"' \
        'ZSH_THEME="robbyrussell"' \
        'ZSH_DISABLE_COMPFIX="true"' \
        'plugins=(git)' \
        'source "$ZSH/oh-my-zsh.sh"' \
        > /home/dev/.zshrc \
    && chown -R 1000:1000 /home/dev

WORKDIR /work

# Default to an interactive zsh; compose mounts the source over /work.
CMD ["/bin/zsh"]
