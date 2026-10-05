#!/usr/bin/env bash
set -euo pipefail

IMAGE="ghcr.io/${REPOSITORY,,}-buildpacks"
RUN_TAG="build-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${IMAGE_RUNTIME}"
SOURCES=()
for ARCH in amd64 arm64; do
  docker image load --input "build/ci-images/buildpacks-${IMAGE_RUNTIME}-${ARCH}/image.tar"
  SOURCE="$IMAGE:$RUN_TAG-$ARCH"
  docker image tag "tolo-idp-base:$IMAGE_RUNTIME-$ARCH" "$SOURCE"
  docker image push "$SOURCE"
  DIGEST=$(docker buildx imagetools inspect "$SOURCE" --format '{{.Manifest.Digest}}')
  SOURCES+=("$IMAGE@$DIGEST")
done

docker buildx imagetools create --tag "$IMAGE:$RUN_TAG" "${SOURCES[@]}"
DIGEST=$(docker buildx imagetools inspect "$IMAGE:$RUN_TAG" --format '{{.Manifest.Digest}}')
echo "image=$IMAGE@$DIGEST" >> "$GITHUB_OUTPUT"
