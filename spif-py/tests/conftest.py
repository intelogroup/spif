from __future__ import annotations

import socket

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--run-live",
        action="store_true",
        default=False,
        help="run tests marked 'live' that require external network/services",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if config.getoption("--run-live"):
        return

    skip_live = pytest.mark.skip(reason="live test skipped by default; pass --run-live to enable")
    for item in items:
        if "live" in item.keywords:
            item.add_marker(skip_live)

    socket_tests = [item for item in items if "local_sockets" in item.keywords]
    if socket_tests:
        probe = socket.socket()
        try:
            probe.bind(("127.0.0.1", 0))
        except OSError:
            skip_sockets = pytest.mark.skip(
                reason="local socket binding is unavailable in this test environment"
            )
            for item in socket_tests:
                item.add_marker(skip_sockets)
        finally:
            probe.close()
