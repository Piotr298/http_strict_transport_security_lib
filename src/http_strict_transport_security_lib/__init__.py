"""Public API for http_strict_transport_security_lib.

This package exposes a single parser for the HTTP Strict-Transport-Security
response header.  The parser is deliberately lenient about whitespace and
case, because real-world servers and proxies vary in how they serialise the
header, but strict about the meaning of the directives it understands.
"""

from .core import HSTSPolicy, parse_hsts

__all__ = ["HSTSPolicy", "parse_hsts"]
