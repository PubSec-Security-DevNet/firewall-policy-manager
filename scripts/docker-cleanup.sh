#!/bin/sh
# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
set -eu

# Compose labels every resource it creates. Restrict routine cleanup to this exact local project
# so unrelated repositories, images, and persistent volumes cannot be removed accidentally.
project="firewall-manager-local"
project_label="com.docker.compose.project=${project}"
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "${script_dir}/.." && pwd)
prune_volumes=false

case "${1:-}" in
  "") ;;
  --volumes) prune_volumes=true ;;
  *)
    echo "Usage: $0 [--volumes]" >&2
    exit 2
    ;;
esac

cd "$repo_root"

expected_images=$(
  docker compose --project-name "$project" config --images |
    sed -e 's/@sha256:.*$//' -e '/:/! s/$/:latest/'
)

docker container prune --force --filter "label=${project_label}"
docker network prune --force --filter "label=${project_label}"
docker image prune --force --filter "label=${project_label}"

# A removed or renamed Compose service can leave a tagged image, so it will not be handled by
# `image prune`. Remove only project-labeled tags absent from the current Compose model.
docker image ls --filter "label=${project_label}" --format '{{.Repository}}:{{.Tag}}' |
  while IFS= read -r image; do
    if [ "$image" != "<none>:<none>" ] &&
      ! printf '%s\n' "$expected_images" | grep --fixed-strings --line-regexp --quiet "$image"; then
      docker image rm "$image"
    fi
  done

if [ "$prune_volumes" = true ]; then
  docker volume prune --all --force --filter "label=${project_label}"
fi

echo "Removed stale Docker resources for ${project}; volumes pruned: ${prune_volumes}."
