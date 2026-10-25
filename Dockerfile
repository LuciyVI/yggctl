FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HYPOTHESIS_STORAGE_DIRECTORY=/tmp/hypothesis \
    XDG_CACHE_HOME=/tmp/cache

WORKDIR /app

# Install the existing QA pins; no application or tests run during the build.
COPY requirements-dev.txt ./
RUN python3 -m pip install --no-cache-dir -r requirements-dev.txt \
    && groupadd --gid 10001 tester \
    && useradd --uid 10001 --gid tester --create-home --shell /usr/sbin/nologin tester \
    && ln -sf /usr/local/bin/python3 /usr/bin/python3

# Some existing subprocess fixtures invoke /usr/bin/python3 explicitly.
COPY pyproject.toml ./
COPY yggctl/ ./yggctl/
COPY tests/ ./tests/

USER tester:tester

ENTRYPOINT ["python3", "-B", "-m", "pytest"]
CMD ["-q", "-p", "no:cacheprovider", "tests/test_fuzz_cli.py", "tests/test_fuzz_peer_inputs.py", "tests/test_fuzz_broker.py", "tests/test_fuzz_acquisition.py", "tests/test_fuzz_archives.py", "tests/test_fuzz_state_io.py", "tests/test_fuzz_outputs.py", "tests/test_fuzz_sender.py"]
