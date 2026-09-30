"""Optional real Redis coverage for atomic password reset operations."""

import os
import shutil
import subprocess
import time

import pytest
from redis import Redis
from redis.exceptions import ConnectionError


@pytest.fixture(scope="session")
def reset_redis_url(tmp_path_factory):
    executable = shutil.which("redis-server") or shutil.which("redis6-server")
    if executable is None:
        url = os.environ.get("TEST_REDIS_URL") or os.environ.get("REDIS_URL")
        if url is None:
            pytest.skip("Real Redis requires redis-server or TEST_REDIS_URL")
        yield url
        return

    directory = tmp_path_factory.mktemp("reset-redis")
    socket = directory / "redis.sock"
    process = subprocess.Popen(
        [executable, "--port", "0", "--unixsocket", str(socket),
         "--save", "", "--appendonly", "no"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )
    url = f"unix://{socket}"
    client = Redis.from_url(url)
    try:
        for _ in range(100):
            try:
                if client.ping():
                    break
            except ConnectionError:
                time.sleep(0.02)
        else:
            pytest.fail("Test Redis did not become ready")
        yield url
    finally:
        client.close()
        process.terminate()
        process.wait(timeout=5)


@pytest.fixture(params=["memory", "redis"])
def reset_backend_url(request):
    if request.param == "redis":
        return request.getfixturevalue("reset_redis_url")
    return None
