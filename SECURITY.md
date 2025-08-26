# Security Policy

## Supported Versions

lib-q is still in active development and pre-release. Security updates are provided for the main development branch and recent releases.

| Version | Supported          |
| ------- | ------------------ |
| main    | ✅                 |
| 0.0.x   | ✅                 |

## Reporting a Vulnerability

We take security vulnerabilities very seriously. If you discover a security issue in lib-q, please report it responsibly.

### Private Security Reports

For critical security vulnerabilities, please use GitHub's private vulnerability reporting feature:

- [GitHub Security Advisories](https://github.com/Enkom-Tech/libQ/security/advisories)

Alternatively, you can report security issues via email to:
- [github@enkom.dev](mailto:github@enkom.dev)

Please include the following information in your report:
- A detailed description of the vulnerability
- Steps to reproduce the issue
- Potential impact and exploit scenarios
- Any proof-of-concept code (if applicable)
- Your contact information for follow-up

### Public Security Reports

For less critical issues or general security questions, you can:
- Open a regular GitHub issue (but please avoid disclosing exploit details publicly)
- Contact the maintainers directly

## Security Considerations

lib-q implements post-quantum cryptographic algorithms that are designed to resist both classical and quantum computer attacks. However, the overall security of any system depends on:

1. **Proper key management**: Keys must be generated securely and stored safely
2. **Secure randomness**: High-quality entropy sources for key generation
3. **Side-channel protection**: Protection against timing and cache attacks
4. **Implementation correctness**: Following cryptographic best practices

## Security Features

lib-q includes several security features:

- **Constant-time operations**: Designed to prevent timing attacks
- **Memory zeroization**: Sensitive data is automatically cleared
- **Input validation**: All inputs are validated before processing
- **No unsafe code**: Strict prohibition of unsafe Rust code
- **Formal verification ready**: Architecture supports formal verification

## Security Audit Status

lib-q is currently under active development. While we follow cryptographic best practices and have implemented security features, the library has not yet undergone a formal third-party security audit.

## Responsible Disclosure

We follow responsible disclosure practices and will:
- Acknowledge receipt of vulnerability reports within 24 hours
- Provide regular updates on the investigation and fix progress
- Coordinate public disclosure timing with the reporter
- Credit researchers for their findings (with permission)

## Security Updates

Security updates will be released as:
- Patch releases (0.0.x) for security fixes
- Security advisories on GitHub
- Announcements in our documentation and release notes

## Contact

For security-related questions or concerns:
- Email: [github@enkom.dev](mailto:github@enkom.dev)
- GitHub: [Enkom-Tech/libQ](https://github.com/Enkom-Tech/libQ)
