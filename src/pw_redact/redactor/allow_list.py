# Copyright 2026 Protocol Wealth LLC
# Licensed under the MIT License
# https://github.com/Protocol-Wealth/pw-redact

"""Layer 4: Allow-list patterns for financial data that must survive redaction."""

from __future__ import annotations

import re

# Regex patterns for financial data that should NEVER be redacted.
# These are checked against detected entity text via re.fullmatch().
ALLOW_PATTERNS: list[str] = [
    # Dollar amounts: $425,000  $50k  $10.50  $1,200,000
    r"\$[\d,]+(?:\.\d{1,2})?(?:[kKmMbB])?",
    # Numbers with commas (must have at least one comma group): 425,000  1,200,000
    r"\d{1,3}(?:,\d{3})+(?:\.\d{1,2})?",
    # Percentages: 32%  6.75%  0.95%
    r"\d+\.?\d*\s*%",
    # Tax bracket references: "32% bracket"  "24% rate"
    r"(?:10|12|22|24|32|35|37)\s*%\s*(?:bracket|rate|tier)",
    # Basis points: 250 bps  50bp
    r"\d+\s*(?:bps?|basis\s+points?)",
    # Planning years: 2024-2099
    r"20[2-9]\d",
    # Ages and milestones: age 59.5  age 70.5  age 65
    r"(?i)age\s+\d{1,3}(?:\.\d)?",
    # IRS form references: Form 1040  Schedule D  IRC §1015
    r"(?:Form|Schedule|IRC\s*§?)\s*[A-Z0-9§.-]+",
    # Financial acronyms
    r"(?:AGI|MAGI|QBI|RMD|QCD|NUA|IRA|SEP|SIMPLE|401k|403b|457b|529|HSA|FSA|W2|W-2|1099)",
    # Mortgage / underwriting / real estate acronyms
    r"(?:LTV|DTI|PMI|PITI|MIP|UFMIP|ARM|FRM|HELOC|HEL)",
    r"(?:TILA|RESPA|ECOA|HMDA|TRID|URLA|QM|ATR)",
    r"(?:DU|LP|AUS|GFE|LE|CD|HUD)",
    r"(?:ALTA|CLTA|CPL|FNMA|FHLMC|GNMA)",
    r"(?:VOE|VOD|VOM|VOR)",
]

# Literal strings passed to Presidio's allow_list parameter.
# These are exact-match exclusions from NLP detection.
ALLOW_TERMS: list[str] = [
    "AGI",
    "MAGI",
    "QBI",
    "RMD",
    "QCD",
    "NUA",
    "IRA",
    "SEP",
    "SIMPLE",
    "HSA",
    "FSA",
    "Roth",
    "FICO",
    "CUSIP",
    "ISIN",
    "ETF",
    "NAV",
    "AUM",
    "EBITDA",
    "P/E",
    "EPS",
    "ROI",
    "ROE",
    "CROIC",
    "W2",
    "W-2",
    "1099",
    # Mortgage / underwriting / real estate
    "LTV",
    "DTI",
    "PMI",
    "PITI",
    "MIP",
    "ARM",
    "FRM",
    "HELOC",
    "TILA",
    "RESPA",
    "ECOA",
    "HMDA",
    "TRID",
    "URLA",
    "ALTA",
    "CLTA",
    "FNMA",
    "FHLMC",
    "GNMA",
    "FHA",
    "HUD",
    "VOE",
    "VOD",
    "VOM",
    "QM",
    "ATR",
    "DU",
    "LP",
    "AUS",
    "GFE",
    "APR",
    "MERS",
    "MLS",
    "HOA",
    "Fannie Mae",
    "Freddie Mac",
    "Ginnie Mae",
]


def compile_allow_patterns() -> list[re.Pattern[str]]:
    """Compile allow-list regex patterns for fullmatch checking."""
    return [re.compile(p) for p in ALLOW_PATTERNS]


def get_allow_terms() -> list[str]:
    """Return literal strings for Presidio's built-in allow_list parameter."""
    return list(ALLOW_TERMS)
