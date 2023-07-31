FROM paritytech/ci-linux:production as build

WORKDIR /code
COPY . .
RUN cargo build --release

FROM ubuntu:20.04
WORKDIR /node

# Copy the node binary.
COPY --from=build /code/target/release/node-template .

# Install root certs, see: https://github.com/paritytech/substrate/issues/9984
RUN apt update && \
    apt install -y ca-certificates && \
    update-ca-certificates && \
    apt remove ca-certificates -y && \
    rm -rf /var/lib/apt/lists/*

EXPOSE 9944
# Exposing unsafe RPC methods is needed for testing but should not be done in
# production.
#CMD [ "./node-template", "--dev", "--ws-external", "--rpc-external"]
ENTRYPOINT ["./node-template"]
