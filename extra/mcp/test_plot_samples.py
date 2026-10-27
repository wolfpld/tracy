"""Needs a saved trace that contains a plot:
    TRACY_TEST_TRACE=/path/to.tracy TRACY_TEST_PLOT=<plot name> python -m pytest extra/mcp/test_plot_samples.py
"""
import os
import time

import pytest

import tracy_mcp

TRACE = os.environ.get("TRACY_TEST_TRACE")
PLOT = os.environ.get("TRACY_TEST_PLOT")
pytestmark = pytest.mark.skipif(not (TRACE and PLOT), reason="TRACY_TEST_TRACE and TRACY_TEST_PLOT not set")


@pytest.fixture(scope="module")
def worker():
    server = tracy_mcp.tracy_server
    w = server.create_worker_from_file(server.open_file(TRACE))
    while not w.is_background_done():
        time.sleep(0.1)
    yield w
    w.shutdown()


def test_whole_window_matches_the_summary(worker):
    summary = next(p for p in worker.get_plots() if p.name == PLOT)
    window = worker.get_plot_window_stats(PLOT)
    assert (window.count, window.min, window.max) == (summary.count, summary.min, summary.max)


def test_two_windows_partition_the_samples(worker):
    first, last = worker.get_first_time(), worker.get_last_time()
    mid = (first + last) // 2
    a = worker.get_plot_window_stats(PLOT, first, mid)
    b = worker.get_plot_window_stats(PLOT, mid, last + 1)
    assert a.count + b.count == worker.get_plot_window_stats(PLOT).count


def test_samples_are_thinned_and_ordered(worker):
    samples = worker.get_plot_samples(PLOT, max_samples=10)
    assert 0 < len(samples) <= 10
    assert [t for t, _ in samples] == sorted(t for t, _ in samples)


def test_unknown_plot_is_empty(worker):
    assert worker.get_plot_samples("no such plot") == []
    assert worker.get_plot_window_stats("no such plot").count == 0
