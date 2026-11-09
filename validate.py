import re

MAX_LENGTH = 500

# Prompt-injection phrases specified in the Project 2 lab instructions.
INJECTION_PATTERNS = [
    r"\bignore\s+(all\s+)?previous\s+instructions\b",
    r"\byou\s+are\s+now\b",
    r"\bpretend\s+you\s+are\b",
    r"\bact\s+as\s+if\s+you\s+have\s+no\b",
]

# Heuristic detection of Base64-like strings containing at least 40 characters.
BASE64_PATTERN = re.compile(
    r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/])"
)


def validate_input(message):
    """Apply Layer 1 (length) and Layer 2 (injection blocklist) checks."""
    if not isinstance(message, str):
        return False, "Invalid input: message must be text."

    if not message.strip():
        return False, "Invalid input: message cannot be empty."

    if len(message) > MAX_LENGTH:
        return False, "Blocked: input exceeds the 500-character limit."

    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, message, flags=re.IGNORECASE):
            return False, "Blocked: possible prompt injection detected."

    if BASE64_PATTERN.search(message):
        return False, "Blocked: Base64-like encoded string of 40+ characters detected."

    return True, "Input accepted."
