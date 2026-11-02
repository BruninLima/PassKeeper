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
