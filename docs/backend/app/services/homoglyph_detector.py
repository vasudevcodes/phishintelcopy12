"""
PhishIntel — Static Unicode Homoglyph & Confusable Detection Engine.
Detects mixed-script homoglyphs, Cyrillic/Greek character substitutions in Latin contexts,
and normalizes lookalike strings for robust downstream heuristic matching.

Purely deterministic, offline, and standard-library based (unicodedata).
"""

import re
import unicodedata
from typing import Dict, List, Optional, Tuple


# Map of Cyrillic and Greek lookalikes to their ASCII Latin visual counterparts
CYRILLIC_LOOKALIKES: Dict[str, str] = {
    "\u0430": "a", "\u0410": "A",  # Cyrillic small/capital a
    "\u0432": "b", "\u0412": "B",  # Cyrillic small/capital ve
    "\u0435": "e", "\u0415": "E",  # Cyrillic small/capital ie
    "\u0455": "s", "\u0405": "S",  # Cyrillic small/capital dze
    "\u0456": "i", "\u0406": "I",  # Cyrillic small/capital byelorussian-ukrainian i
    "\u0458": "j", "\u0408": "J",  # Cyrillic small/capital je
    "\u043a": "k", "\u041a": "K",  # Cyrillic small/capital ka
    "\u043c": "m", "\u041c": "M",  # Cyrillic small/capital em
    "\u043d": "h", "\u041d": "H",  # Cyrillic small/capital en (visual H)
    "\u043e": "o", "\u041e": "O",  # Cyrillic small/capital o
    "\u0440": "p", "\u0420": "P",  # Cyrillic small/capital er (visual P)
    "\u0441": "c", "\u0421": "C",  # Cyrillic small/capital es (visual C)
    "\u0442": "t", "\u0422": "T",  # Cyrillic small/capital te
    "\u0443": "y", "\u0423": "Y",  # Cyrillic small/capital u (visual y)
    "\u0445": "x", "\u0425": "X",  # Cyrillic small/capital ha (visual x)
}

GREEK_LOOKALIKES: Dict[str, str] = {
    "\u03b1": "a", "\u0391": "A",  # Greek small/capital alpha
    "\u03b2": "b", "\u0392": "B",  # Greek small/capital beta
    "\u03b5": "e", "\u0395": "E",  # Greek small/capital epsilon
    "\u03b9": "i", "\u0399": "I",  # Greek small/capital iota
    "\u03ba": "k", "\u039a": "K",  # Greek small/capital kappa
    "\u03bd": "v", "\u039d": "N",  # Greek small nu / capital nu
    "\u03bf": "o", "\u039f": "O",  # Greek small/capital omicron
    "\u03c1": "p", "\u03a1": "P",  # Greek small/capital rho
    "\u03c4": "t", "\u03a4": "T",  # Greek small/capital tau
    "\u03c5": "u", "\u03a5": "Y",  # Greek small/capital upsilon
    "\u03c7": "x", "\u03a7": "X",  # Greek small/capital chi
}

HOMOGLYPH_LOOKALIKE_MAP: Dict[str, str] = {**CYRILLIC_LOOKALIKES, **GREEK_LOOKALIKES}


def normalize_homoglyphs(text: Optional[str]) -> str:
    """
    Normalizes Cyrillic and Greek lookalike characters to their Latin equivalents.
    Preserves all standard Latin, punctuation, whitespace, and legitimate non-lookalike characters.
    """
    if not text:
        return ""
    return "".join(HOMOGLYPH_LOOKALIKE_MAP.get(c, c) for c in text)


def detect_mixed_script_homoglyphs(text: Optional[str]) -> List[Dict[str, str]]:
    """
    Detects tokens that mix Latin characters with Cyrillic or Greek lookalikes,
    or tokens consisting entirely of lookalike characters designed to visually emulate Latin words.

    Returns a list of detected homoglyph occurrences with:
    - original: original token with lookalikes
    - normalized: ASCII/Latin normalized token
    - substituted_chars: list of replaced characters with their Unicode names
    """
    if not text:
        return []

    # Tokenize word-like segments including hyphens and underscores
    tokens = re.findall(r"[a-zA-Z\u0400-\u04FF\u0370-\u03FF0-9_-]+", text)
    detected: List[Dict[str, str]] = []

    for token in tokens:
        has_latin = any("LATIN" in unicodedata.name(c, "") for c in token)
        lookalikes_found = [c for c in token if c in HOMOGLYPH_LOOKALIKE_MAP]

        # Mixed script: Latin + Lookalikes, OR full lookalike token containing typical spoofed letters
        if (has_latin and lookalikes_found) or (len(lookalikes_found) >= 2 and len(lookalikes_found) == len([c for c in token if c.isalpha()])):
            norm_token = normalize_homoglyphs(token)
            if norm_token.lower() != token.lower():
                char_details = [
                    f"'{c}' (U+{ord(c):04X} {unicodedata.name(c, '')} -> '{HOMOGLYPH_LOOKALIKE_MAP[c]}')"
                    for c in lookalikes_found
                ]
                detected.append({
                    "original": token,
                    "normalized": norm_token,
                    "substituted_chars": ", ".join(char_details),
                })

    return detected


def has_mixed_script_homoglyphs(text: Optional[str]) -> bool:
    """Fast check whether text contains mixed-script homoglyphs."""
    return len(detect_mixed_script_homoglyphs(text)) > 0
