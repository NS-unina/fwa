# Ubuntu 20.04 is the last Ubuntu release that packages phantomjs (amd64 and arm64).
FROM ubuntu:20.04

# phantomjs runs the XSS analyzer headless; procps provides the ps/pgrep that fwa
# and the benchmark driver use to stop and wait for mitmdump; tini reaps the
# mitmdump and web-server processes fwa starts in the background.
ENV DEBIAN_FRONTEND=noninteractive \
    QT_QPA_PLATFORM=offscreen \
    PYTHONUNBUFFERED=1
RUN apt-get update \
    && apt-get install --yes --no-install-recommends phantomjs procps tini ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# fwa needs Python ^3.10, which Ubuntu 20.04 does not package: a pinned standalone
# CPython from uv, and fwa's locked dependencies (poetry.lock) installed by poetry.
COPY --from=ghcr.io/astral-sh/uv:0.5.11 /uv /usr/local/bin/uv
ARG PYTHON_VERSION=3.10.16
ARG POETRY_VERSION=1.8.3
ENV UV_PYTHON_INSTALL_DIR=/opt/python \
    UV_TOOL_DIR=/opt/uv-tools \
    UV_TOOL_BIN_DIR=/usr/local/bin \
    VIRTUAL_ENV=/opt/venv \
    PATH=/opt/venv/bin:$PATH
RUN uv python install "${PYTHON_VERSION}" \
    && uv venv --python "${PYTHON_VERSION}" /opt/venv \
    && uv tool install --python "${PYTHON_VERSION}" "poetry==${POETRY_VERSION}"
WORKDIR /opt/fwa
COPY pyproject.toml poetry.lock README.md ./
COPY fwa ./fwa
RUN poetry install --only main --no-interaction --no-ansi

# interactsh-client registers the payload domains of the out-of-band payloads
# (*_OAST) and polls their interactions; pinned by version and SHA-256.
ARG TARGETARCH
ENV INTERACTSH_CLIENT_VERSION=1.2.4
RUN apt-get update \
    && apt-get install --yes --no-install-recommends curl unzip \
    && case "${TARGETARCH}" in \
         amd64) sum=d6728561b0db2266d2e301773b2fcf9079f6fe402ebae477bc6e92775cab9a72 ;; \
         arm64) sum=c5b36d2ddf20c2524cbfc7174e66ef0e2abe9d1ece222917d8b0a5676e55568f ;; \
         *) echo "no interactsh-client release for ${TARGETARCH}" >&2; exit 1 ;; \
       esac \
    && curl --fail --silent --show-error --location --output /tmp/interactsh-client.zip \
         "https://github.com/projectdiscovery/interactsh/releases/download/v${INTERACTSH_CLIENT_VERSION}/interactsh-client_${INTERACTSH_CLIENT_VERSION}_linux_${TARGETARCH}.zip" \
    && echo "${sum}  /tmp/interactsh-client.zip" | sha256sum --check - \
    && unzip -o /tmp/interactsh-client.zip interactsh-client -d /usr/local/bin \
    && rm /tmp/interactsh-client.zip \
    && apt-get purge --yes curl unzip && apt-get autoremove --yes && rm -rf /var/lib/apt/lists/*

COPY payloads.csv ./
COPY benchmark ./benchmark

RUN useradd --create-home fwa && mkdir --parents /results && chown fwa:fwa /results
USER fwa
WORKDIR /home/fwa
VOLUME ["/results"]
ENTRYPOINT ["tini", "--", "python", "/opt/fwa/benchmark/fwa_scan.py", "--payloads", "/opt/fwa/payloads.csv", "--classes", "/opt/fwa/benchmark/classes.json"]
CMD ["--help"]
