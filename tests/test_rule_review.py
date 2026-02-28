"""Review pairs for benign collisions the catalog intentionally tolerates."""

import unittest

from yara_lab import scanner

# (Rule identifier, scenario, benign input that matches, similar input that does not.)
REVIEW_PAIRS = (
    (
        "Synthetic_Archive_Tag",
        "format teaching example with a longer tag",
        b"YLAB\x01\x00\x00\x00training-archives\nexample, no archive contents\n",
        b"YLAB\x01\x00\x00\x00training-catalog\nexample, no archive contents\n",
    ),
    (
        "Synthetic_Intake_Note",
        "status substring quoted in a draft comment",
        b"LAB-INTAKE/1\ncomment=example status=training-only-draft\n",
        b"LAB-INTAKE/1\ncomment=example status=training-draft\n",
    ),
    (
        "Synthetic_Observer_Rollcall",
        "two seats and a third token shown as an instruction",
        b"LAB-ROLLCALL/1\n[seat:observer]\n[seat:observer]\nHelp: use [seat:observer]\n",
        b"LAB-ROLLCALL/1\n[seat:observer]\n[seat:observer]\nHelp: choose a seat\n",
    ),
    (
        "Synthetic_Practice_Receipt",
        "blank template with a sample ID and trailing instructions",
        b"LAB-RECEIPT/1\nreceipt_id=R0000\nmode=practice\nReplace the sample ID.\n",
        b"LAB-RECEIPT/1\nreceipt_id=R0000\nmode=practice draft\nReplace the sample ID.\n",
    ),
    (
        "Synthetic_Review_Trace",
        "quoted fields spread across separate log entries",
        b"Example LAB-REVIEW/1\nDay 1: queue=fixture-review\nDay 2: decision=manual-check\n",
        b"Example LAB-REVIEW/1\nDay 1: queue=fixture-review\nDay 2: queue=fixture-review\n",
    ),
)


class RuleReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = scanner.compile_catalog()

    def test_review_pairs_cover_every_compiled_rule_once(self):
        self.assertCountEqual(
            [identifier for identifier, _, _, _ in REVIEW_PAIRS],
            [rule.identifier for rule in self.rules],
        )

    def test_review_pairs_have_exact_match_lists(self):
        for identifier, scenario, hit, miss in REVIEW_PAIRS:
            for data, expected in ((hit, [identifier]), (miss, [])):
                with self.subTest(
                    rule=identifier, scenario=scenario, expected=expected
                ):
                    self.assertEqual(scanner.match_names(self.rules, data), expected)
