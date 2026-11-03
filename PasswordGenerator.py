#!/usr/bin/env python3
"""Passphrase generator (e.g. ``Tiger-482-Ocean-Pencil``).

Based on password-generator-py by Gabriel Bordeaux (gabfl):
https://github.com/gabfl/password-generator-py

Changes for PassKeeper: uses the ``secrets`` module (cryptographically secure)
instead of ``random``, finds the word list relative to this file (or inside a
PyInstaller bundle) instead of a hard-coded Windows path, and caches the list.
"""

import argparse
import secrets
import sys
from functools import lru_cache
from pathlib import Path

SEPARATORS = ('-', '_', ':', ';', '.', '=', '+', '%', '*')


def dictionary_path() -> Path:
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return base / "data" / "english.csv"


@lru_cache(maxsize=None)
def load_dictionary(min_word_length=3, max_word_length=8):
    """Return the tuple of words whose length is within the given bounds."""
    with open(dictionary_path(), 'r', encoding='utf-8') as dict_file:
        words = tuple(
            word for word in (line.strip() for line in dict_file)
            if min_word_length <= len(word) <= max_word_length
        )
    if not words:
        raise ValueError("No dictionary words match the requested lengths.")
    return words


def get_random_word(min_word_length=3, max_word_length=8):
    return secrets.choice(load_dictionary(min_word_length, max_word_length))


def get_random_separator(no_special_characters=False):
    return '' if no_special_characters else secrets.choice(SEPARATORS)


def get_random_int(max_int_value):
    """Random number between 0 and ``max_int_value`` (inclusive)."""
    return secrets.randbelow(max_int_value + 1)


def pw(min_word_length=3, max_word_length=8, max_int_value=1000,
       number_of_elements=4, no_special_characters=False):
    """Generate a password made of words plus one number."""
    if number_of_elements < 1:
        raise ValueError("number_of_elements must be at least 1")
    int_position = secrets.randbelow(number_of_elements)

    parts = []
    for i in range(number_of_elements):
        if i == int_position:
            parts.append(str(get_random_int(max_int_value)))
        else:
            parts.append(get_random_word(min_word_length, max_word_length).title())
        if i != number_of_elements - 1:
            parts.append(get_random_separator(no_special_characters))
    return ''.join(parts)


def generate():
    """To use the module within another module."""
    return pw()


def passphrase(words=4, separator=None, capitalize=True, include_number=True):
    """Words joined by a separator, e.g. ``Ocean-Tiger-Pencil-Cloud-58``.

    ``separator=None`` picks a random separator between each word."""
    if words < 1:
        raise ValueError("Use at least one word.")
    parts = [get_random_word(3, 8) for _ in range(words)]
    if capitalize:
        parts = [p.title() for p in parts]
    if include_number:
        parts.insert(secrets.randbelow(len(parts) + 1), str(secrets.randbelow(1000)))
    if separator is not None:
        return separator.join(parts)
    out = parts[0]
    for part in parts[1:]:
        out += secrets.choice(SEPARATORS) + part
    return out


# --------------------------------------------------------------------------- #
# Random-character passwords
# --------------------------------------------------------------------------- #

LOWER = "abcdefghijklmnopqrstuvwxyz"
UPPER = LOWER.upper()
DIGITS = "0123456789"
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/~"
AMBIGUOUS = set("Il1O0o")


def random_password(length=20, lower=True, upper=True, digits=True, symbols=True,
                    avoid_ambiguous=False):
    """Random characters, with at least one of every chosen kind."""
    groups = [g for g, wanted in ((LOWER, lower), (UPPER, upper), (DIGITS, digits),
                                  (SYMBOLS, symbols)) if wanted]
    if avoid_ambiguous:
        groups = ["".join(c for c in g if c not in AMBIGUOUS) for g in groups]
    if not groups:
        raise ValueError("Choose at least one kind of character.")
    if length < len(groups):
        raise ValueError(f"The length must be at least {len(groups)}.")
    alphabet = "".join(groups)
    chars = [secrets.choice(g) for g in groups]
    chars += [secrets.choice(alphabet) for _ in range(length - len(groups))]
    # Fisher-Yates shuffle with a secure random source
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)


# --------------------------------------------------------------------------- #
# Strength estimate
# --------------------------------------------------------------------------- #

COMMON_PASSWORDS = {
    "password", "passw0rd", "123456", "12345678", "123456789", "1234567890", "qwerty",
    "qwertyuiop", "abc123", "111111", "letmein", "iloveyou", "admin", "welcome",
    "monkey", "dragon", "football", "baseball", "sunshine", "princess", "master",
    "senha", "senha123", "123mudar", "mudar123",
}
STRENGTH_LABELS = ((28, "Very weak"), (40, "Weak"), (60, "Fair"), (80, "Strong"))


def _pool_size(text):
    pool = 0
    if any(c in LOWER for c in text):
        pool += 26
    if any(c in UPPER for c in text):
        pool += 26
    if any(c in DIGITS for c in text):
        pool += 10
    if any(not c.isalnum() for c in text):
        pool += 33
    if any(ord(c) > 127 for c in text):
        pool += 100
    return pool


def estimate_strength(password):
    """Rough guess of how hard a password is to crack.

    Returns (bits, label). Word-based passwords are counted per dictionary word,
    and common passwords or a single dictionary word with a few extra digits/
    symbols are rated as what they are: easy to guess."""
    import math
    if not password:
        return 0, "Very weak"
    lowered = password.casefold()
    if lowered in COMMON_PASSWORDS or len(set(password)) <= 2:
        return 5, "Very weak"

    words = set(load_dictionary(3, 12))
    dict_bits = math.log2(max(len(words), 2))

    # Split into words/numbers/other pieces and score each piece.
    import re
    bits = 0.0
    pieces = re.findall(r"[A-Za-z]+|\d+|[^A-Za-z\d]+", password)
    for piece in pieces:
        if piece.isalpha() and piece.casefold() in words:
            bits += dict_bits + (1 if not piece.islower() else 0)
        elif piece.isdigit():
            bits += len(piece) * math.log2(10)
        else:
            bits += len(piece) * math.log2(max(_pool_size(piece), 2))
    if len(pieces) > 1:
        bits += math.log2(len(pieces))   # where the pieces go
    # never rate higher than the plain brute-force estimate
    bits = min(bits, len(password) * math.log2(max(_pool_size(password), 2)))
    bits = int(bits)
    for limit, label in STRENGTH_LABELS:
        if bits < limit:
            return bits, label
    return bits, "Very strong"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-n", "--min_word_length", type=int,
                        help="Minimum length for each word", default=3)
    parser.add_argument("-x", "--max_word_length", type=int,
                        help="Maximum length for each word", default=8)
    parser.add_argument("-i", "--max_int_value", type=int,
                        help="Maximum value for the integer", default=1000)
    parser.add_argument("-e", "--number_of_elements", type=int,
                        help="Number of elements in the password (ie. 4 = 3 words + 1 integer)",
                        default=4)
    parser.add_argument("-s", "--no_special_characters",
                        action='store_true', help="Do not use special characters")
    args = parser.parse_args()
    print(pw(min_word_length=args.min_word_length,
             max_word_length=args.max_word_length,
             max_int_value=args.max_int_value,
             number_of_elements=args.number_of_elements,
             no_special_characters=args.no_special_characters))


if __name__ == "__main__":
    main()
