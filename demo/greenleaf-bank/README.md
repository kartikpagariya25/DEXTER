# GreenLeaf Bank (Demo)

A small, deliberately vulnerable codebase for demonstrating Dexter's SAVR loop.
Not a real application. Do not deploy. Do not reuse any pattern here.

Contains, on purpose: a hardcoded JWT signing secret, CORS misconfiguration,
SQL injection via string concatenation, dynamic command execution (JS and
Python), TLS verification disabled, XSS via unescaped HTML rendering,
unquoted secrets in `.env`, and an outdated/vulnerable npm dependency set
for dependency-CVE scanning.
