FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    g++ \
    cmake \
    make \
    python3 \
    python3-pip \
    valgrind \
    linux-tools-generic \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace/packet-rush

COPY . .

RUN make clean && make

CMD ["make", "test"]
