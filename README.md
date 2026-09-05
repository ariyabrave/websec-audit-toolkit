# WebSec Audit Toolkit

A modular Web and API security assessment toolkit written in Python.

## Status

Early development.

## Current Features

- Command-line interface
- HTTP/HTTPS target validation
- URL normalization
- HTTP response retrieval
- Redirect handling
- Request timeout and connection error handling
- HTTP security header analysis
- Structured security findings
- Automated unit tests

### Security Headers

The toolkit currently checks for:

- Content-Security-Policy
- Strict-Transport-Security
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy


## Purpose

This project is intended for authorized security testing, local security labs, and security education.

## Usage

```bash
websec scan example.com