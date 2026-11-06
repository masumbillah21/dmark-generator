# SPF · DKIM · DMARC Generator

A small, dependency-free web tool that generates the DNS TXT records needed for email authentication. It runs entirely in the browser — no backend, no data sent anywhere. DKIM keys are generated locally with the Web Crypto API.

## Files

| File | Purpose |
|------|---------|
| `index.html` | Page markup |
| `style.css` | Styles (light and dark mode) |
| `app.js` | SPF, DKIM and DMARC logic |

## Running

With Laragon running, open `http://dmark-generator.test` or `http://localhost/dmark-generator/`.

Or serve the folder with any static server:

```bash
php -S localhost:8000
```

DKIM generation needs a secure context, so use `https://` or `localhost` (not a plain-HTTP LAN address).

## Features

### SPF
- Authorize `mx` and `a` records, IPv4/IPv6 addresses and ranges, and other domains via `include:`
- Quick-select providers: Google Workspace, Microsoft 365, Zoho, SendGrid, Mailgun, Amazon SES, Mailchimp, Postmark, Brevo, SparkPost
- Choose the default qualifier: `~all`, `-all`, `?all`, `+all`
- Counts DNS lookups against the limit of 10 and skips invalid IPs

### DKIM
- RSA 1024 / 2048 / 4096-bit key pair generated in the browser
- Outputs the `selector._domainkey` host, the `v=DKIM1; k=rsa; p=…` value, and a version split into 255-character strings for zone files
- Private key in PKCS#8 PEM with a download button

### DMARC
- Policy (`p`), subdomain policy (`sp`), `pct`, `fo`, `adkim`, `aspf`
- Aggregate (`rua`) and forensic (`ruf`) report addresses, validated
- Outputs the `_dmarc` host and value

### Verify
- Looks up your live DNS records via DNS-over-HTTPS (Google DNS, with Cloudflare as fallback) and reports **PASS / WARNING / NOT FOUND** for each
- SPF: detects missing or duplicate records, `+all`, a missing `all`, and the 10-lookup limit
- DKIM: checks `selector._domainkey.domain`, that a public key is present, its approximate size, and testing mode
- DMARC: checks `_dmarc.domain`, the policy tags, and whether `rua` is set
- Requires internet access; the domain and selector are sent to the DNS resolver

## Publishing the records

Add each as a **TXT** record at your DNS provider:

| Record | Host | Example value |
|--------|------|---------------|
| SPF | `@` | `v=spf1 a include:_spf.google.com ~all` |
| DKIM | `selector._domainkey` | `v=DKIM1; k=rsa; p=MIIBIjANBg…` |
| DMARC | `_dmarc` | `v=DMARC1; p=none; rua=mailto:dmarc@example.com` |

Some providers append the domain automatically; enter only the host part (e.g. `_dmarc`, not `_dmarc.example.com`) in that case.

## Notes

- Only **one** SPF record is allowed per domain. Merge with any existing `v=spf1` record.
- Keep the DKIM **private key secret** and install it on your mail server. Hosted providers (Google, Microsoft, SendGrid, etc.) generate DKIM keys for you, so this is mainly for self-hosted mail.
- Start DMARC at `p=none`, review the reports, then move to `quarantine` and `reject`.
- DMARC passes only when SPF and/or DKIM pass **and align** with the From domain.
- DNS changes can take time to propagate. Verify with `nslookup -type=TXT _dmarc.example.com` or `dig TXT`.
