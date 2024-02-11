# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.21-alpine AS base-builder

SHELL ["/bin/ash", "-euxo", "pipefail", "-c"]

# Informational
ARG TARGETPLATFORM
ARG BUILDPLATFORM
RUN echo "I am running on $BUILDPLATFORM, building for $TARGETPLATFORM."

# Environment variables
ENV CGO_ENABLED 0
ENV CHECKPOINT_DISABLE true

# Install Packages
RUN apk upgrade --update --no-cache
RUN apk add --no-cache \
    bash \
    coreutils \
    curl \
    git \
    gpg \
    jq \
    openssh-client \
    util-linux-misc \
    xz \
    zip \
    ;

#-------------------------------------------------------------------------------

FROM base-builder AS base-golangci
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]

ENV GOLANGCI_LINT_VERSION 1.54.2
RUN curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b "$(go env GOPATH)/bin" "v${GOLANGCI_LINT_VERSION}"
RUN golangci-lint --version

#-------------------------------------------------------------------------------

FROM base-builder AS base-markdown-table-formatter
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]

RUN go install github.com/skyzyx/markdown-table-formatter@latest

#-------------------------------------------------------------------------------

FROM base-builder AS final
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]

RUN mkdir -p /root/.ssh
RUN ssh-keyscan -H "github.com" >> /root/.ssh/known_hosts

# Copy over from layers
COPY --from=base-golangci /go/bin/golangci-lint /go/bin/golangci-lint
COPY --from=base-markdown-table-formatter /go/bin/markdown-table-formatter /go/bin/markdown-table-formatter

# Cleanup
RUN rm -Rf /tmp/*
RUN find /tmp -type f -print0 | xargs -0 rm -Rf

# Code mounted here
WORKDIR /workspace

# Default to running a bash shell
ENTRYPOINT ["/bin/bash", "--login"]

# Environment variables
ENV CGO_ENABLED 0

# https://docs.docker.com/engine/reference/builder/#environment-replacement
ENV PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin:/go/bin"
RUN echo 'export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin:/go/bin"' > /root/.bashrc
RUN echo 'source /root/.bashrc' > /root/.profile

#-------------------------------------------------------------------------------

FROM --platform=$BUILDPLATFORM golang@sha256:0ff68fa7b2177e8d68b4555621c2321c804bcff839fd512c2681de49026573b7 AS fake-second-base
FROM --platform=$BUILDPLATFORM ghcr.io/adrianchifor/harpoon:latest AS fake-third-base
