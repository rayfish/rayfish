# Cross build container for x86_64-unknown-linux-gnu, pinned to Ubuntu 22.04
# (glibc 2.35). cross's default `:main` image is Ubuntu 24.04 (glibc 2.39), which
# links `ray` against symbols older hosts don't have, so it fails at startup with
# `GLIBC_2.39 not found`. 22.04 is the newest Ubuntu our Scaleway servers run; a
# binary built here also runs on newer (24.04) hosts. The tree is C-free (ring,
# no OpenSSL/aws-lc), so a plain toolchain image is all cross needs.
FROM ubuntu:22.04

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential ca-certificates \
 && rm -rf /var/lib/apt/lists/*
