"""
Run the in-memory h2 + wsproto RFC 8441 example as a test.

The ``h2`` package is not a wsproto dependency, so this test is skipped
when it is not installed.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from wsproto.frame_protocol import CloseReason

if TYPE_CHECKING:
    from types import ModuleType

pytestmark = pytest.mark.skipif(
    importlib.util.find_spec("h2") is None,
    reason="requires the h2 package",
)

EXAMPLE = Path(__file__).parent.parent / "example" / "h2_extended_connect.py"


def load_example() -> ModuleType:
    spec = importlib.util.spec_from_file_location("h2_extended_connect", EXAMPLE)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_h2_extended_connect_example() -> None:
    summary = load_example().main()
    assert summary["fragmented_text"] == "Hello, fragmented world!"
    assert summary["compressed_payload"] == "compressible payload " * 40
    assert summary["reset_close_code"] is CloseReason.ABNORMAL_CLOSURE
    assert summary["post_reset_reply"] == "still with me?"
