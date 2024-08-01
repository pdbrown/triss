# syntax=docker/dockerfile:1.7.1
#                          ^- pin latest version on 2024-05-23

FROM debian:stable as base

WORKDIR /app
RUN <<EOF bash
    set -ex
    apt-get update
    apt-get install -y python3
EOF


FROM base as builder

WORKDIR /build

# venv setup
RUN <<EOF bash
    set -ex
    apt-get install -y python3-venv
    python3 -m venv --without-pip /venv
    python3 -m venv /venv-builder
EOF

# install app into venv
COPY --link dist dist

RUN <<EOF bash
    set -ex

    # Activate /venv-builder
    export PATH="/venv-builder/bin:${PATH}"
    export VIRTUAL_ENV=/venv-builder

    # Configure pip
    export PIP_DEFAULT_TIMEOUT=100
    export PIP_DISABLE_PIP_VERSION_CHECK=1
    export PIP_NO_CACHE_DIR=1

    # User /venv-builder's pip to install into /venv
    pip --python /venv/bin/python install triss --find-links /build/dist
EOF


FROM base as app

RUN apt-get install -y qrencode zbar-tools

COPY --from=builder --link /venv /venv

# Don't write .pyc files. They won't survive a container restart anyway.
ENV PYTHONDONTWRITEBYTECODE=1

# Activate /venv
ENV PATH="/venv/bin:${PATH}"
ENV VIRTUAL_ENV=/venv

ENTRYPOINT ["/venv/bin/triss"]
