FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash coreutils findutils grep sed gawk \
    python3 python3-pip \
    gdb gdbserver \
    binutils file patchelf \
    libc6-dbg \
    procps \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 可选：装 pwntools（很多人用它的 checksec/ELF 解析）
RUN python3 -m pip install --no-cache-dir --upgrade pip \
    && python3 -m pip install --no-cache-dir pwntools

WORKDIR /workspace
