# Security Documentation

## Overview

This document describes the security features and considerations for the `check-tls` project.

## SSRF Protection

### What is SSRF?

Server-Side Request Forgery (SSRF) is a vulnerability where an attacker can make the server initiate requests to internal or arbitrary destinations. In the context of `check-tls`, an attacker could potentially:

- Scan internal network ports for TLS services
- Enumerate internal hosts
- Access services not exposed publicly
- Bypass firewall rules

### Protection Mechanisms

Starting from version 1.8.0, `check-tls` includes built-in SSRF protection that blocks connections to private and internal IP addresses.

#### Blocked IP Ranges

The following IP ranges are blocked by default:

**IPv4:**
- `10.0.0.0/8` - Private network (RFC1918)
- `172.16.0.0/12` - Private network (RFC1918)
- `192.168.0.0/16` - Private network (RFC1918)
- `127.0.0.0/8` - Loopback (RFC1122)
- `169.254.0.0/16` - Link-local (RFC3927)
- `0.0.0.0/8` - Current network (RFC1122)
- `100.64.0.0/10` - Shared address space (RFC6598)
- `192.0.0.0/24` - IETF protocol assignments (RFC6890)
- `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` - Documentation (RFC5737)
- `198.18.0.0/15` - Benchmarking (RFC2544)
- `224.0.0.0/4` - Multicast (RFC5771)
- `240.0.0.0/4` - Reserved (RFC1112)
- `255.255.255.255/32` - Broadcast (RFC919)

**IPv6:**
- `::1/128` - Loopback (RFC4291)
- `fe80::/10` - Link-local (RFC4291)
- `fc00::/7` - Unique local address (RFC4193)
- `ff00::/8` - Multicast (RFC4291)
- `::ffff:0:0/96` - IPv4-mapped IPv6 (RFC4291)
- `2001:db8::/32` - Documentation (RFC3849)

#### How It Works

1. When analyzing a domain, `check-tls` first validates the target host
2. If the host is an IP address, it checks against the blocklist
3. If the host is a domain name, it resolves the domain to IP addresses
4. All resolved IP addresses are checked against the blocklist
5. If any resolved IP is in a blocked range, the connection is refused

### Disabling SSRF Protection

**⚠️ WARNING**: Only disable SSRF protection in trusted, isolated environments (e.g., development, testing).

To allow connections to internal IPs, set the environment variable:

```bash
# Temporarily allow internal IPs for current session
export ALLOW_INTERNAL_IPS=true
check-tls 192.168.1.1

# Or inline for a single command
ALLOW_INTERNAL_IPS=true check-tls 192.168.1.1

# For web server
ALLOW_INTERNAL_IPS=true check-tls --server
```

### Security Best Practices

#### For Deployment

1. **Never disable SSRF protection in production** unless you have additional network-level controls
2. **Use network segmentation** - Deploy `check-tls` in a DMZ or isolated network segment
3. **Implement rate limiting** - Use a reverse proxy (nginx, Traefik) to limit requests
4. **Monitor logs** - Watch for repeated attempts to access internal IPs
5. **Keep dependencies updated** - Regularly update Python and all dependencies

#### For Development

1. **Use environment variables** - Configure `ALLOW_INTERNAL_IPS` only when needed
2. **Test with safe targets** - Use public test domains for functional testing
3. **Review logs** - Check security validation messages in debug mode

#### Example Secure Deployment

```bash
# Docker deployment with security in mind
docker run -d \
  --name check-tls \
  --network isolated-network \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges:true \
  -p 127.0.0.1:8000:8000 \
  check-tls:latest --server
```

## XSS Protection

The web interface includes HTML escaping for all user-controlled data to prevent Cross-Site Scripting (XSS) attacks. Certificate fields (CN, Subject, Issuer, SANs) are sanitized before being displayed in the browser.

## Reporting Security Issues

If you discover a security vulnerability, please report it to:

**Email**: obeone@obeone.org
**Subject**: [SECURITY] check-tls vulnerability report

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will respond within 48 hours and work with you to address the issue.

## Security Changelog

### Version 1.8.0 (2025)
- Added SSRF protection with IP blocklist validation
- Added XSS protection with HTML escaping in web interface
- Added `ALLOW_INTERNAL_IPS` environment variable for controlled bypass
- Created `security_utils.py` module for centralized security validations

## Additional Resources

- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
