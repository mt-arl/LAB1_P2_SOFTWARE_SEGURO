"""Representación léxica compartida por el entrenamiento y el análisis local."""

import re

FEATURE_VERSION = 1
CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
LEXEME = re.compile(r"[a-z]+|\d+(?:\.\d+)?")
ASSIGN = re.compile(
    r"""(?P<key>[\w.-]+)["']?\s*[:=](?![=>])\s*"""
    r"""(?P<value>["'][^"'\n]{0,160}["']|[\w.-]+)"""
)
INLINE_COMMENT = re.compile(r"""(?:"[^"\\]*(?:\\.[^"\\]*)*"|'[^'\\]*(?:\\.[^'\\]*)*')|(?P<comment>\s*(?:\#|//).*)""")
ALIASES = {
    "ownership": "owner", "owned": "owner", "proprietor": "owner",
    "authorization": "authorize", "authz": "authorize",
    "verification": "verify", "verificationrequired": "verify", "validate": "verify",
    "validated": "verify", "validation": "verify", "check": "verify", "checking": "verify",
    "debugging": "debug", "diagnostics": "debug", "diagnostic": "debug",
    "tracebacks": "debug", "traceback": "debug", "stacktrace": "debug",
    "encryption": "encrypt", "encrypted": "encrypt", "secure": "secure",
    "expiry": "expire", "expiration": "expire", "expires": "expire", "ttl": "expire",
    "requests": "request", "limits": "limit", "limiter": "limit", "limiting": "limit",
    "throttle": "limit", "throttling": "limit", "quota": "limit",
    "enabled": "enable", "required": "require", "enforce": "require",
    "enforced": "require", "max": "limit", "maximum": "limit",
    "on": "true", "off": "false", "yes": "true", "no": "false",
    "true": "true", "false": "false", "null": "unset", "none": "unset",
    "undefined": "unset", "unlimited": "unset", "never": "unset",
}
SECURITY_TERMS = {
    "auth", "authenticate", "authorize", "api", "certificate", "cors", "debug",
    "encrypt", "expire", "http", "https", "jwt", "limit", "owner", "rate",
    "request", "session", "tls", "token", "transport",
}
STATE_TERMS = {"true", "false", "unset", "zero", "number", "https", "http"}


def without_comment(line):
    for match in INLINE_COMMENT.finditer(line):
        if match.group("comment") is not None:
            return line[:match.start()]
    return line


def tokens(text):
    result = []
    for raw in LEXEME.findall(CAMEL.sub(" ", text).lower()):
        if raw[0].isdigit():
            result.append("zero" if float(raw) == 0 else "number")
        else:
            result.append(ALIASES.get(raw, raw))
    return result


def features(text):
    words = tokens(text)
    result = {f"w:{word}" for word in words}
    result.update(f"b:{left}/{right}" for left, right in zip(words, words[1:]))
    for match in ASSIGN.finditer(text):
        key_terms = set(tokens(match.group("key")))
        value_terms = tokens(match.group("value"))
        if not value_terms or value_terms[0] not in STATE_TERMS:
            continue
        state = value_terms[0]
        for term in key_terms:
            result.add(f"a:{term}={state}")
    anchors = set(words) & SECURITY_TERMS
    for anchor in anchors:
        for qualifier in set(words) & (STATE_TERMS | {"require", "verify", "enable"}):
            result.add(f"c:{anchor}/{qualifier}")
    return result


def eligible(text):
    words = set(tokens(text))
    return bool(words & SECURITY_TERMS and words & STATE_TERMS)


def api_context(path, source):
    words = set(tokens(f"{path} {source}"))
    return bool(words & {"api", "endpoint", "fastapi", "flask", "express", "router", "openapi"})


def evidence(line):
    """Expone el patrón y oculta el contenido de literales arbitrarios."""
    text = without_comment(line).strip()
    text = re.sub(
        r"""(["'])(?:\\.|(?!\1).)*\1""",
        lambda match: match[0] if (
            re.match(r"\s*:", text[match.end():])
            and set(tokens(match[0])) & SECURITY_TERMS
        ) else "<literal omitido>",
        text,
    )
    return text[:320]
