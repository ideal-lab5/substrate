# FROM paritytech/ci-linux:production as build

# WORKDIR /code
# COPY . .
# RUN cargo build --release

# FROM ubuntu:20.04
# WORKDIR /node

# # Copy the node binary.
# COPY --from=build /code/target/release/node-template .

# # Install root certs, see: https://github.com/paritytech/substrate/issues/9984
# RUN apt update && \
#     apt install -y ca-certificates && \
#     update-ca-certificates && \
#     apt remove ca-certificates -y && \
#     rm -rf /var/lib/apt/lists/*

# EXPOSE 9944
# # Exposing unsafe RPC methods is needed for testing but should not be done in
# # production.
# CMD [ "./node-template", "--dev", "--ws-external", "--rpc-methods=Unsafe" ]


FROM phusion/baseimage:0.11 as builder
LABEL maintainer="driemworks@idealabs.network"
LABEL description="This is the build stage for etf. Here we create the binary."

ENV DEBIAN_FRONTEND=noninteractive

ARG PROFILE=release
WORKDIR /etf

COPY . /etf

RUN apt-get update && \
	apt-get dist-upgrade -y -o Dpkg::Options::="--force-confold" && \
	apt-get install -y cmake pkg-config libssl-dev git clang protobuf-compiler && \
	apt-get install -y wget

# build etf
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y && \
	export PATH="$PATH:$HOME/.cargo/bin" && \
	rustup toolchain install nightly && \
	rustup target add wasm32-unknown-unknown --toolchain nightly && \
	rustup default stable && \
	cargo build "--$PROFILE"

# ===== SECOND STAGE ======

FROM phusion/baseimage:0.11
LABEL maintainer="driemworks@idealabs.network"
LABEL description="This is the 2nd stage: a very small image where we copy the binary."
ARG PROFILE=release

# add user
RUN useradd -m -u 1000 -U -s /bin/sh -d /etf etf
COPY --from=builder /etf/target/$PROFILE/substrate-node /usr/local/bin

# checks
RUN ldd /usr/local/bin/substrate-node && \
	/usr/local/bin/substrate-node --version

# Shrinking
RUN rm -rf /usr/lib/python* && \
	rm -rf /usr/bin /usr/sbin /usr/share/man

USER etf
# expose node endpoints
EXPOSE 30333 9933 9944 9615
VOLUME ["/data"]
#  could replace by CMD later on but this is useful for testing
ENTRYPOINT ["/usr/local/bin/substrate-node"]