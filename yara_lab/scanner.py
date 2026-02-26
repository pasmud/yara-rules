"""Load the bundled catalog and scan a bounded snapshot of a local file."""

import os
import stat
from pathlib import Path

import yara

CATALOG = Path(__file__).resolve().parents[1] / "rules" / "synthetic.yar"
MAX_SAMPLE_BYTES = 1024 * 1024
MATCH_TIMEOUT_SECONDS = 2


class InputError(ValueError):
    """The sample is outside the scanner's supported inputs."""


def compile_catalog() -> yara.Rules:
    return yara.compile(filepath=str(CATALOG), includes=False, error_on_warning=True)


def _open_nonblocking(path: str, flags: int) -> int:
    # Opening a FIFO must not wait for a writer before we can reject it with fstat.
    return os.open(path, flags | os.O_NONBLOCK)


def read_sample(path: Path) -> bytes:
    with open(path, "rb", opener=_open_nonblocking) as sample:
        if not stat.S_ISREG(os.fstat(sample.fileno()).st_mode):
            raise InputError(f"not a regular file: {path}")
        data = sample.read(MAX_SAMPLE_BYTES + 1)
    if len(data) > MAX_SAMPLE_BYTES:
        raise InputError(f"file exceeds {MAX_SAMPLE_BYTES} bytes: {path}")
    return data


def match_names(rules: yara.Rules, data: bytes) -> list[str]:
    """Match an in-memory sample under the same size limit as a file scan."""
    if len(data) > MAX_SAMPLE_BYTES:
        raise InputError(f"sample exceeds {MAX_SAMPLE_BYTES} bytes")
    return sorted(
        match.rule for match in rules.match(data=data, timeout=MATCH_TIMEOUT_SECONDS)
    )
