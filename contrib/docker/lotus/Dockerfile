FROM ubuntu:24.04
ARG RELEASE_ARCHIVE
COPY "${RELEASE_ARCHIVE}" /tmp/release.tar.gz
# Ubuntu 24.04 release ELF dependencies: libevent, pthread support, Berkeley DB,
# and the C++ runtime. Remaining libc/libgcc dependencies are installed by apt.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libevent-2.1-7t64 libevent-pthreads-2.1-7t64 libdb5.3++t64 libstdc++6 \
    && rm -rf /var/lib/apt/lists/* \
    && tar xzf /tmp/release.tar.gz -C /usr/local --strip-components=1 \
    && rm /tmp/release.tar.gz
RUN groupadd -r lotus && useradd -rmg lotus lotus \
    && mkdir /data && chown lotus:lotus /data \
    && ln -s /data /home/lotus/.lotus
VOLUME /data
EXPOSE 10604 10605
USER lotus
CMD ["lotusd", "-datadir=/data"]
