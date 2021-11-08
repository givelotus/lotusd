#!/usr/bin/env bash

export LC_ALL=C

set -euxo pipefail

: "${SDK_DL_REMOTE:=}"

usage() {
  echo "Usage: download-apple-sdk.sh dest_dir"
  echo "The SDK_DL_REMOTE environment variable should be set to a URL pointing to the folder containing the SDK archive, with no trailing /."
  echo "Output: prints the SDK file name"
}

if [ -z "${SDK_DL_REMOTE}" ] || [ $# -ne 1 ]; then
  usage
  exit 1
fi

DEST_DIR="$1"

: "${TOPLEVEL:=$(git rev-parse --show-toplevel)}"

OSX_SDK="Xcode-11.3.1-11C505-extracted-SDK-with-libcxx-headers.tar.gz"
OSX_SDK_SHA256="436df6dfc7073365d12f8ef6c1fdb060777c720602cc67c2dcf9a59d94290e38"

pushd "${DEST_DIR}" > /dev/null
if ! echo "${OSX_SDK_SHA256}  ${OSX_SDK}" | sha256sum --quiet -c > /dev/null 2>&1; then
  rm -f "${OSX_SDK}"
  wget -q https://bitcoincore.org/depends-sources/sdks/"${OSX_SDK}"
  echo "${OSX_SDK_SHA256}  ${OSX_SDK}" | sha256sum --quiet -c
fi
popd > /dev/null

echo "${OSX_SDK}"
