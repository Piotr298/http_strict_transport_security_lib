# http_strict_transport_security_lib

Parse the `Strict-Transport-Security` HTTP response header into a small,
typed object.

```python
from http_strict_transport_security_lib import parse_hsts, HSTSPolicy

policy = parse_hsts("max-age=63072000; includeSubDomains; preload")
assert policy == HSTSPolicy(max_age=63072000, include_subdomains=True, preload=True)

assert parse_hsts("") is None
assert parse_hsts("includeSubDomains") is None
assert parse_hsts("max-age=abc") is None
```

The exported names are `parse_hsts` and `HSTSPolicy`.  `parse_hsts` takes the
raw header value (no header name) and returns `HSTSPolicy | None`.
`HSTSPolicy` is a frozen dataclass with fields `max_age` (int),
`include_subdomains` (bool), and `preload` (bool).

## Why this exists

HSTS is a security header, so a parser that silently accepts a malformed
value is worse than one that rejects it: the caller may believe a policy is
in force when it is not.  This library therefore returns `None` for any
header that does not contain a valid `max-age` directive, including an empty
header, a bare `max-age`, a negative value, or a non-integer value.  That is
the one decision the rest of the API is built around.

The trade-off is leniency about formatting.  Directive names are matched
case-insensitively, whitespace around `=` is stripped, unknown directives
are ignored, and duplicate directives resolve to the last occurrence.  Real
servers and proxies emit all of these variations, and rejecting them would
not make anyone safer.

## The awkward edge

A header such as `max-age=31536000; max-age=abc` returns `None`, because the
last `max-age` wins and it is invalid.  If you need the first valid value
instead, parse the header yourself; this library deliberately follows the
browser rule of last-occurrence-wins.
