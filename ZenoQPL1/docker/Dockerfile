FROM rust:1.92 AS builder
RUN apt-get update && apt-get install -y \
    build-essential \
    clang \
    cmake \
    libclang-dev \
    llvm-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
RUN export LIBCLANG_PATH="$(llvm-config --libdir)" \
    && cargo build --release --bin zeno-cli

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/zeno-cli /usr/local/bin/zeno-cli
ENTRYPOINT ["zeno-cli"]
