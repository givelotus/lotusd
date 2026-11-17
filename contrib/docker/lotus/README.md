# Lotus release container

Download `lotus-v12.7.1-x86_64-linux-gnu.tar.gz` and its SHA256SUMS from
https://github.com/givelotus/lotus/releases/tag/v12.7.1. Verify the checksum
before building. Run from this directory with the archive beside the Dockerfile:

```sh
docker build -t lotus:12.7.1 --build-arg RELEASE_ARCHIVE=lotus-v12.7.1-x86_64-linux-gnu.tar.gz .
docker run --rm -v lotus-data:/data lotus:12.7.1
```

The volume must be writable by the container user. RPC remains bound to loopback;
configure authentication and network exposure explicitly. No image is published
by the release-preparation script. Release CI builds this image and checks lotusd/lotus-cli --version. It does not publish an image or run a synchronized container node.
