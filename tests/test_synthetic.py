import os
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from itertools import combinations
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import yara

from yara_lab import scanner
from yara_lab.__main__ import main

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "intake-note.txt"
INTAKE_HEADER = b"LAB-INTAKE/1\n"
INTAKE_STATUS = b"status=training-only\n"
INTAKE = INTAKE_HEADER + INTAKE_STATUS
REVIEW_MARKER = b"LAB-REVIEW/1"
REVIEW_FIELDS = (
    b"queue=fixture-review",
    b"decision=manual-check",
    b"owner=training-desk",
)
ARCHIVE_HEADER = b"YLAB\x01\x00"
ARCHIVE_TAG = b"training-archive"
RECEIPT = b"LAB-RECEIPT/1\nreceipt_id=R0427\nmode=practice"
ROLLCALL_HEADER = b"LAB-ROLLCALL/1\n"
OBSERVER_SEAT = b"[seat:observer]"


def archive_at(offset: int) -> bytes:
    return ARCHIVE_HEADER + bytes(offset - len(ARCHIVE_HEADER)) + ARCHIVE_TAG


class RuleRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Import and compile the real engine unconditionally; failure is a test error.
        cls.rules = scanner.compile_catalog()

    def assert_matches(self, data, *expected):
        self.assertEqual(scanner.match_names(self.rules, data), list(expected))

    def test_intake_note_lf_and_crlf(self):
        for data in (INTAKE, INTAKE.replace(b"\n", b"\r\n")):
            with self.subTest(data=data):
                self.assert_matches(data, "Synthetic_Intake_Note")

    def test_intake_near_misses(self):
        for data in (
            b"x" + INTAKE,
            b"LAB-INTAKE/10\nstatus=training-only\n",
            b"LAB-INTAKE/1\nstatus=training\n",
            INTAKE.lower(),
        ):
            with self.subTest(data=data):
                self.assert_matches(data)

    def test_review_any_two_distinct_fields(self):
        for pair in combinations(REVIEW_FIELDS, 2):
            with self.subTest(pair=pair):
                self.assert_matches(
                    b"\n".join((REVIEW_MARKER, *pair)), "Synthetic_Review_Trace"
                )

    def test_review_rejects_duplicates_and_missing_marker(self):
        for data in (
            b"\n".join((REVIEW_MARKER, REVIEW_FIELDS[0], REVIEW_FIELDS[0])),
            b"\n".join(REVIEW_FIELDS),
            REVIEW_MARKER,
        ):
            with self.subTest(data=data):
                self.assert_matches(data)

    def test_archive_tag_accepts_both_offset_endpoints(self):
        for offset in (8, 31):
            with self.subTest(offset=offset):
                self.assert_matches(archive_at(offset), "Synthetic_Archive_Tag")

    def test_archive_tag_rejects_offsets_outside_range(self):
        for offset in (7, 32):
            with self.subTest(offset=offset):
                self.assert_matches(archive_at(offset))

    def test_archive_rejects_bad_header_and_truncation(self):
        valid = archive_at(8)
        for data in (
            b"X" + valid[1:],
            b"YLAB\x02\x00" + valid[6:],
            b"YLAB\x01\x01" + valid[6:],
            valid[:5],
            valid[:-1],
        ):
            with self.subTest(data=data):
                self.assert_matches(data)

    def test_receipt_accepts_eof_and_line_endings(self):
        for data in (
            RECEIPT,
            RECEIPT + b"\noperator_note=sample\n",
            (RECEIPT + b"\n").replace(b"\n", b"\r\n"),
            RECEIPT.replace(b"\n", b"\r\n", 1),
        ):
            with self.subTest(data=data):
                self.assert_matches(data, "Synthetic_Practice_Receipt")

    def test_receipt_rejects_malformed_opening_records(self):
        for data in (
            b"note\n" + RECEIPT,
            RECEIPT.replace(b"R0427", b"R042"),
            RECEIPT.replace(b"R0427", b"R04270"),
            RECEIPT.replace(b"R0427", b"R04Z7"),
            b"LAB-RECEIPT/1\nmode=practice\nreceipt_id=R0427",
            RECEIPT + b"-draft\n",
        ):
            with self.subTest(data=data):
                self.assert_matches(data)

    def test_rollcall_counts_literal_occurrences(self):
        for data in (
            ROLLCALL_HEADER + OBSERVER_SEAT * 3,
            b"LAB-ROLLCALL/1\r\n" + b"\r\n".join([OBSERVER_SEAT] * 3),
        ):
            with self.subTest(data=data):
                self.assert_matches(data, "Synthetic_Observer_Rollcall")

    def test_rollcall_rejects_wrong_counts_and_headers(self):
        for data in (
            ROLLCALL_HEADER + OBSERVER_SEAT * 2 + b"[seat:Observer]",
            ROLLCALL_HEADER + OBSERVER_SEAT * 4,
            b"LAB-ROLLCALL/10\n" + OBSERVER_SEAT * 3,
            b"notes\n" + ROLLCALL_HEADER + OBSERVER_SEAT * 3,
            OBSERVER_SEAT * 3,
        ):
            with self.subTest(data=data):
                self.assert_matches(data)

    def test_matches_are_sorted_for_multiple_rules(self):
        data = b"\n".join((archive_at(8), REVIEW_MARKER, *REVIEW_FIELDS))
        self.assert_matches(data, "Synthetic_Archive_Tag", "Synthetic_Review_Trace")

    def test_unrelated_text_binary_and_empty_inputs(self):
        for data in (b"Inventory notes: training complete.\n", bytes(range(256)), b""):
            with self.subTest(data=data):
                self.assert_matches(data)


class CliTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory(dir=ROOT, prefix=".test-")
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)

    def run_cli(self, *args, without_dependencies=False):
        flags = ["-E", "-S"] if without_dependencies else []
        return subprocess.run(
            [sys.executable, *flags, "-m", "yara_lab", *args],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    def assert_error(self, result, message):
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertIn(message, result.stderr)

    def test_check(self):
        result = self.run_cli("check")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "Catalog compiled.\n")
        self.assertEqual(result.stderr, "")

    def test_scan_documented_example(self):
        result = self.run_cli("scan", str(EXAMPLE))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "Synthetic_Intake_Note\n")
        self.assertEqual(result.stderr, "")

    def test_scan_clean_file(self):
        result = self.run_cli("scan", "LICENSE")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")

    def test_scan_symlink_to_regular_file(self):
        link = self.directory / "sample-link.txt"
        link.symlink_to(EXAMPLE)
        result = self.run_cli("scan", str(link))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "Synthetic_Intake_Note\n")

    def test_exact_size_limit_is_scanned(self):
        sample = self.directory / "at-limit.bin"
        padding = scanner.MAX_SAMPLE_BYTES - len(INTAKE)
        # Keep the required status at the end so a truncated read cannot pass.
        sample.write_bytes(INTAKE_HEADER + bytes(padding) + INTAKE_STATUS)
        result = self.run_cli("scan", str(sample))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "Synthetic_Intake_Note\n")

    def test_one_byte_over_limit_is_rejected_even_with_match(self):
        sample = self.directory / "over-limit.bin"
        sample.write_bytes(INTAKE + bytes(scanner.MAX_SAMPLE_BYTES + 1 - len(INTAKE)))
        self.assert_error(self.run_cli("scan", str(sample)), "exceeds 1048576 bytes")

    def test_missing_file(self):
        result = self.run_cli("scan", str(self.directory / "missing.txt"))
        self.assert_error(result, "missing.txt")

    def test_directory(self):
        self.assert_error(self.run_cli("scan", str(self.directory)), "error:")

    def test_fifo_is_rejected_without_waiting_for_a_writer(self):
        fifo = self.directory / "sample.fifo"
        os.mkfifo(fifo)
        self.assert_error(self.run_cli("scan", str(fifo)), "not a regular file")

    def test_missing_scan_argument(self):
        self.assert_error(self.run_cli("scan"), "the following arguments are required")

    def test_missing_engine_is_an_error_not_a_skip(self):
        result = self.run_cli("check", without_dependencies=True)
        self.assert_error(result, "could not import yara-python")
        self.assertIn("requirements.txt", result.stderr)

    def test_invalid_catalog_fails_check(self):
        catalog = self.directory / "invalid.yar"
        catalog.write_text("rule Synthetic_Invalid { condition: }", encoding="ascii")
        with patch.object(scanner, "CATALOG", catalog):
            self.assert_main_error(["check"], "catalog compilation failed")

    def test_catalog_warning_fails_check(self):
        catalog = self.directory / "warning.yar"
        catalog.write_text(
            'rule Synthetic_Short { strings: $literal = "a" condition: $literal }',
            encoding="ascii",
        )
        with patch.object(scanner, "CATALOG", catalog):
            self.assert_main_error(["check"], "may slow down scanning")

    def test_engine_timeout_is_reported_as_an_error(self):
        # Inject the exception to exercise reporting without a slow/flaky fixture.
        with patch.object(scanner, "match_names", side_effect=yara.TimeoutError):
            self.assert_main_error(["scan", str(EXAMPLE)], "YARA scan timed out")

    def assert_main_error(self, args, message):
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = main(args)
        self.assertEqual(status, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn(message, stderr.getvalue())
