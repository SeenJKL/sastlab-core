# Replication image for SASTLab. Everything that is pinned is pinned here:
#   Python 3.14 + the exact packages in requirements.lock (includes Semgrep 1.178.0),
#   CodeQL CLI 2.27.1 python bundle (SHA-256 checked) which ships codeql/python-queries 1.8.11,
#   Bandit 1.9.4 (requirements-bandit.lock) and Pysa (pyre-check 0.10.0, requirements-pysa.lock), each in its own environment, with the stock models in third_party/pysa-models.
# The saved experiment results (results/, about 0.4 GB) are not copied into the image.
#
#   docker build -t sastlab .
#   docker run --rm sastlab                       # offline checks: unit and integration test suite
#   docker run --rm -e SOCLAAS_API_KEY=... sastlab ./run.sh doctor      # only the LLM strategies need the key
FROM python:3.14-slim-bookworm

ARG CODEQL_VERSION=2.27.1
ARG CODEQL_SHA256=ea86393c6c812542ae5a3a7122bcc760873707a50b25cc47d2fd7cfd514b0cb0

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl zstd \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/sastlab

COPY requirements.lock .
RUN python -m venv .sastlab/.venv \
 && .sastlab/.venv/bin/pip install --no-cache-dir -r requirements.lock

COPY requirements-pysa.lock .
RUN python -m venv .sastlab/pysa-venv \
 && .sastlab/pysa-venv/bin/pip install --no-cache-dir -r requirements-pysa.lock

COPY requirements-bandit.lock .
RUN python -m venv .sastlab/bandit-venv \
 && .sastlab/bandit-venv/bin/pip install --no-cache-dir -r requirements-bandit.lock

RUN curl -fsSL -o /tmp/codeql.tar.zst \
      "https://github.com/github/codeql-action/releases/download/codeql-bundle-v${CODEQL_VERSION}/codeql-bundle-python-linux64.tar.zst" \
 && echo "${CODEQL_SHA256}  /tmp/codeql.tar.zst" | sha256sum -c - \
 && mkdir -p .sastlab/tools \
 && zstd -dc /tmp/codeql.tar.zst | tar -x -C .sastlab/tools \
 && rm /tmp/codeql.tar.zst

COPY . .

# No systemd inside the container, so the CPU cap of run.sh is off; limit CPUs with `docker run --cpus`.
ENV SASTLAB_CPU_LIMIT=0 PYTHONDONTWRITEBYTECODE=1
CMD [".sastlab/.venv/bin/python", "-m", "pytest", "-q", "-p", "no:cacheprovider"]
