#!/usr/bin/env bash
PODMAN=podman 

${PODMAN} run --rm \
  --userns=keep-id \
  -v "$(pwd)":/mnt -w /mnt \
  --entrypoint /home/whistler/whistler \
       whistler:latest "$@"

