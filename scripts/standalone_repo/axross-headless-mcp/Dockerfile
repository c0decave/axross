# axross-headless-mcp in a container: this repository's own package, run as
# an unprivileged user, read-only and confined to /data unless told otherwise.
#
#   docker build -t axross-headless-mcp .
#   docker run -i --rm -v "$PWD:/data" axross-headless-mcp            # read-only
#   docker run -i --rm -v "$PWD:/data" axross-headless-mcp \
#       --mcp-root /data --mcp-write --mcp-tools all                  # everything
#
# The release image (ghcr.io/c0decave/axross-headless-mcp) is built by axross's
# release workflow from Dockerfile.mcp; this file is for directories that build
# from the repository (Glama, the Docker MCP Catalog) and for local builds.
# Pin the base by digest with --build-arg PYTHON_IMAGE=python:3.12-slim@sha256:...
ARG PYTHON_IMAGE=python:3.12-slim
FROM ${PYTHON_IMAGE}

LABEL io.modelcontextprotocol.server.name="io.github.c0decave/axross-headless-mcp"
LABEL org.opencontainers.image.title="axross-headless-mcp" \
      org.opencontainers.image.source="https://github.com/c0decave/axross-headless-mcp" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY . /src
RUN pip install --no-cache-dir /src \
    && rm -rf /src \
    && useradd --create-home --uid 10001 mcp \
    && mkdir -p /data \
    && chown mcp /data

USER mcp
WORKDIR /data
VOLUME /data
ENTRYPOINT ["axross-headless-mcp"]
CMD ["--mcp-root", "/data"]
