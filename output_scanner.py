import re

CREDENTIAL_PATTERNS = [
    r"\bpassword\s*=",
    r"\bapi[\s_-]*key\s*=",
    r"\btoken\s*=",
]


def scan_output(response, system_prompt=""):
    """
    Layer 3: inspect model output for the configured system prompt,
    credential-like assignments, and HTTP/HTTPS URLs.
    """
    if not isinstance(response, str):
        return False, "Blocked: invalid model response."

    if system_prompt and system_prompt.strip() in response:
        return False, "Blocked: system prompt disclosure detected."

    for pattern in CREDENTIAL_PATTERNS:
        if re.search(pattern, response, flags=re.IGNORECASE):
            return False, "Blocked: possible credential disclosure detected."

    if re.search(r"https?://\S+", response, flags=re.IGNORECASE):
        return False, "Blocked: external URL detected."

    return True, "Output accepted."
