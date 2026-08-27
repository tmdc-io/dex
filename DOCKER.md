# Building the Dex Docker Image (TMDC)

This document describes how to build and publish the TMDC Dex image
`docker.io/tmdcio/dex`.

## Prerequisites

- Docker with [Buildx](https://docs.docker.com/build/buildx/) enabled
- Git
- Make

## Local build

From the repository root:

```bash
make build-tmdc-docker GITHUB_TAGS=2.45.1-d1
```

This builds:

```text
docker.io/tmdcio/dex:2.45.1-d1
```

The build uses `Dockerfile.dataos` and injects `VERSION` from `GITHUB_TAGS`.

### Optional variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GITHUB_TAGS` | current git branch name | Image tag |
| `PLATFORM` | `linux/amd64` | Target platform |
| `TMDC_IMAGE` | `docker.io/tmdcio/dex` | Image name |
| `DOCKER_BUILD_ARGS` | _(empty)_ | Extra `docker buildx build` args |

Examples:

```bash
# Explicit tag and platform
make build-tmdc-docker GITHUB_TAGS=2.45.1-d1 PLATFORM=linux/amd64

# Custom image name
make build-tmdc-docker GITHUB_TAGS=2.45.1-d1 TMDC_IMAGE=docker.io/tmdcio/dex
```

## Push locally

Log in to Docker Hub, then push:

```bash
docker login
make push-tmdc-docker GITHUB_TAGS=2.45.1-d1
```

## CI build (recommended)

The workflow [`.github/workflows/tmdc-docker-build-push.yaml`](.github/workflows/tmdc-docker-build-push.yaml)
builds and pushes the image when you push a git tag matching `*-d*`
(for example `2.45.1-d1` or `v2.45.1-d1`).

### Required GitHub secrets

This repo does not inherit Docker Hub credentials automatically. Login fails with
`Username and password required` until these secrets exist **on `tmdc-io/dex`**
(or the org secrets are granted to this repository):

- `DOCKER_HUB_USERNAME`
- `DOCKER_HUB_PASSWORD`

`DOCKER_USERNAME` / `DOCKER_PASSWORD` are also accepted as a fallback.

Add them under **Settings → Secrets and variables → Actions**. If they already
exist as organization secrets (they do on Quickwit), open the org secret and
add `tmdc-io/dex` to the repository access list. Then re-run the workflow.

### Trigger a build

```bash
git tag 2.45.1-d1
git push origin 2.45.1-d1
```

CI will:

1. Check out the tagged commit
2. Build `docker.io/tmdcio/dex:<tag>` for `linux/amd64`
3. Push the image to Docker Hub

### Tag pattern

| Tag | Triggers workflow? |
|-----|--------------------|
| `2.45.1-d1` | Yes |
| `v2.45.1-d1` | Yes |
| `2.45.1` | No |
| `v2.45.1` | No |

## Run the image

```bash
docker run --rm docker.io/tmdcio/dex:2.45.1-d1 --version
```
