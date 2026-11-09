"""Parser for the HTTP Strict-Transport-Security (HSTS) header.

The header is defined by RFC 6797.  Its grammar is a semicolon-separated
list of directives, only one of which (``max-age``) carries a value.  The
other two directives, ``includeSubDomains`` and ``preload``, are flags.

Design decisions worth calling out:

*   Directive names are matched case-insensitively.  RFC 6797 section 6.1
    defines them in lowercase, but servers have been observed sending
    ``IncludeSubDomains`` and ``PRELOAD``.  Rejecting those would be
    unhelpful and would not improve security.

*   ``max-age`` is required for a policy to be considered valid.  A header
    without ``max-age`` cannot be enforced, so we return ``None`` rather
    than a policy with a default age.  This mirrors the requirement in
    RFC 6797 section 6.1.1.

*   Duplicate directives are resolved by taking the last occurrence.  This
    is the same rule browsers use for repeated ``max-age`` values and avoids
    a parser that silently keeps the first value while a later one is what
    the server actually meant.

*   Unknown directives are ignored.  RFC 6797 requires that they be ignored
    so that future extensions do not break existing clients.

*   Whitespace around directive names and values is stripped.  Some servers
    emit ``max-age = 31536000`` with spaces around the ``=``; that is not
    strictly legal, but it is common enough that rejecting it would be
    unhelpful.

*   The value of ``max-age`` must be a non-negative decimal integer.  A
    negative or non-numeric value invalidates the whole header, because a
    policy with an unparseable age cannot be enforced.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class HSTSPolicy:
    """A parsed HSTS policy.

    Attributes:
        max_age: Number of seconds the policy is valid for.  Always a
            non-negative integer.
        include_subdomains: Whether the ``includeSubDomains`` directive was
            present.
        preload: Whether the ``preload`` directive was present.
    """

    max_age: int
    include_subdomains: bool
    preload: bool


def parse_hsts(header: str) -> HSTSPolicy | None:
    """Parse an HSTS header value.

    Args:
        header: The raw value of the ``Strict-Transport-Security`` header,
            without the header name.  May be empty.

    Returns:
        An :class:`HSTSPolicy` if the header contains a valid ``max-age``
        directive, otherwise ``None``.  ``None`` is also returned for an
        empty header, because an empty header is not a policy.
    """
    if header is None:
        return None

    max_age: int | None = None
    include_subdomains = False
    preload = False

    for raw_directive in header.split(";"):
        directive = raw_directive.strip()
        if not directive:
            continue

        # Split once so that a value containing '=' (which would be invalid
        # for max-age anyway) does not confuse the flag handling below.
        name, sep, value = directive.partition("=")
        name = name.strip().lower()
        value = value.strip()

        if name == "max-age":
            if not sep:
                # A bare max-age has no value and cannot be enforced.
                return None
            if not value.isdigit():
                # Reject negative numbers, floats, and anything else that
                # is not a run of decimal digits.  isdigit() also rejects
                # an empty string, which is what we want.
                return None
            max_age = int(value)
        elif name == "includesubdomains":
            # RFC 6797 defines this as a flag; a value is ignored.
            include_subdomains = True
        elif name == "preload":
            preload = True
        # Unknown directives are deliberately ignored.

    if max_age is None:
        return None

    return HSTSPolicy(
        max_age=max_age,
        include_subdomains=include_subdomains,
        preload=preload,
    )
