# Web Security Header Checker

`header_checker.py` checks a website's HTTP security headers, cookie flags,
CORS behavior, HTTPS transport, and potentially revealing response headers.
It prints findings, a score, a letter grade, and suggested fixes. Reports can
also be saved as JSON or HTML.

## Requirements

- Python 3.8 or newer
- `requests`

Install the dependency:

```bash
python -m pip install requests
```

## Usage

The checker asks for confirmation that you are authorized to test the target.
You can provide `--yes` to confirm non-interactively:

```bash
python header_checker.py https://example.com
python header_checker.py example.com --json report.json
python header_checker.py example.com --html report.html
python header_checker.py example.com --timeout 20 --yes
```

If no scheme is supplied, the checker uses HTTPS. The timeout is in seconds
and defaults to 10.

## Authorization and limitations

Only test sites you own or have explicit permission to assess. This is a
best-effort checker of observable HTTP behavior, not a penetration test or
proof that a site is secure. Findings depend on the target's responses and
should be reviewed in context.
