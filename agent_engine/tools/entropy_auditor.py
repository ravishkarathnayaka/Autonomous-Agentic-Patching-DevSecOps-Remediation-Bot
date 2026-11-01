"""Shannon entropy analyzer for detecting exposed credentials, API keys, and cryptographic secrets."""

import collections
import math
import re
from typing import List, Tuple


class EntropyAuditor:
    """Calculates Shannon entropy to detect high-entropy secrets and credentials in source code diffs."""

    DEFAULT_THRESHOLD = 4.2
    MIN_TOKEN_LENGTH = 16

    @classmethod
    def calculate_shannon_entropy(cls, text: str) -> float:
        """Compute the Shannon entropy (in bits per character) of a string.

        Args:
            text: Input string.

        Returns:
            Shannon entropy as float.
        """
        if not text:
            return 0.0

        length = len(text)
        counts = collections.Counter(text)
        entropy = 0.0

        for count in counts.values():
            p_x = count / length
            entropy -= p_x * math.log2(p_x)

        return entropy

    @classmethod
    def find_high_entropy_tokens(
        cls,
        text: str,
        threshold: float = DEFAULT_THRESHOLD,
        min_length: int = MIN_TOKEN_LENGTH
    ) -> List[Tuple[str, float]]:
        """Identify candidate secret tokens exceeding entropy threshold.

        Args:
            text: Text to scan.
            threshold: Minimum Shannon entropy (default 4.2).
            min_length: Minimum length of string token (default 16).

        Returns:
            List of tuples (token: str, entropy: float).
        """
        tokens = re.findall(r"[a-zA-Z0-9_\-\+\/]{" + str(min_length) + r",}", text)
        high_entropy: List[Tuple[str, float]] = []

        for token in set(tokens):
            ent = cls.calculate_shannon_entropy(token)
            if ent >= threshold:
                high_entropy.append((token, round(ent, 3)))

        return sorted(high_entropy, key=lambda x: x[1], reverse=True)
