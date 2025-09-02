FROM ubuntu:24.04@sha256:7c06e91f61fa88c08cc74f7e1b7c69ae24910d745357e0dfe1d2c0322aaf20f9 AS chroot

RUN apt-get update && \
    apt-get --assume-yes --no-install-recommends install socat && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY ./app /app
WORKDIR /app

RUN chmod +x chall
CMD sh start.sh