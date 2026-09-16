import time

from dexter.progress import Spinner, _is_tty


def test_spinner_is_noop_without_a_real_terminal(monkeypatch):
    monkeypatch.setattr("dexter.progress._is_tty", lambda: False)
    ran = []

    with Spinner("doing work"):
        ran.append(True)

    assert ran == [True]


def test_spinner_does_not_block_or_delay_the_wrapped_work(monkeypatch):
    monkeypatch.setattr("dexter.progress._is_tty", lambda: False)
    start = time.time()

    with Spinner("quick"):
        pass

    assert time.time() - start < 0.5


def test_is_tty_returns_bool_without_raising():
    assert isinstance(_is_tty(), bool)
