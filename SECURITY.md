# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take the security of Kayan seriously. If you discover a security vulnerability, please follow these steps:

### 1. Do Not Create a Public Issue

Security vulnerabilities should **not** be reported through public GitHub issues.

### 2. Email Us Directly

Send your report to: **security@getkayan.io**

Include the following information:
- Type of vulnerability (e.g., authentication bypass, SQL injection, XSS)
- Step-by-step instructions to reproduce
- Proof of concept (if available)
- Impact assessment
- Any suggested fixes

### 3. Response Timeline

| Action | Timeline |
|--------|----------|
| Acknowledgment | Within 48 hours |
| Initial assessment | Within 5 business days |
| Resolution target | Within 30 days (severity dependent) |

### 4. What to Expect

- We will acknowledge receipt of your report
- We will investigate and validate the issue
- We will work on a fix and coordinate disclosure
- We will credit you in the security advisory (unless you prefer anonymity)

## Security Best Practices

When deploying Kayan:

- Always use HTTPS in production
- Use strong, unique secrets for JWT signing
- Enable rate limiting and account lockout
- Keep dependencies up to date
- Store database credentials securely
- Regularly rotate secrets and tokens

## Disclosure Policy

We follow responsible disclosure practices:

1. Reporter submits vulnerability privately
2. We validate and develop a fix
3. We release the fix and publish a security advisory
4. Full details are disclosed after users have time to update

Thank you for helping keep Kayan and its users safe!
