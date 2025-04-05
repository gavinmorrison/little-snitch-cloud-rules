# 🔒 Little Snitch Cloud Rules Generator

<p align="center">
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.7+-blue.svg" alt="Python 3.7+"></a>
  <a href="https://github.com/gavinmorrison/little-snitch-cloud-rules/actions"><img src="https://img.shields.io/github/actions/workflow/status/gavinmorrison/little-snitch-cloud-rules/generate-cloud-rules.yml?branch=main" alt="GitHub Workflow Status"></a>
  <a href="https://pypi.org/project/requests/"><img src="https://img.shields.io/badge/requests-2.25.1+-green.svg" alt="Requests"></a>
  <a href="https://github.com/gavinmorrison/little-snitch-cloud-rules/commits/main"><img src="https://img.shields.io/github/last-commit/gavinmorrison/little-snitch-cloud-rules.svg" alt="Last Updated"></a>
  <img src="https://img.shields.io/badge/macOS-compatible-brightgreen.svg" alt="macOS Compatible">
  <img src="https://img.shields.io/badge/Little%20Snitch-compatible-orange.svg" alt="Little Snitch Compatible">
</p>

This repository provides a Python script that fetches endpoint data from cloud service providers (initially only Microsoft) and generates **[Little Snitch](https://www.obdev.at/products/littlesnitch/index.html)** rule files to allow or restrict outbound traffic.

---

## Overview

This script:
- **Fetches** official cloud service provider endpoint lists (currently Microsoft; future expansion possible).
- **Extracts** relevant URLs and IPs.
- **Generates** a `.lsrules` rule file formatted for **Little Snitch** on macOS.
- **Supports updating rules using GitHub Actions**, ensuring rule files stay up-to-date.

## Features & Limitations

**New Features:**
- **Automated rule generation:** GitHub Actions runs the script daily to fetch updated endpoint lists.
- **Port-specific rule generation:** Optionally generate separate rules for TCP and UDP ports.
- **Enhanced URL handling:** Wildcard domains are correctly processed (mostly).

**Limitations:**
- **Wildcard limitations:** Only leading wildcards are supported (e.g. `*.microsoft.com`); as of March 2025, this impacts two URLs: `autodiscover.*.onmicrosoft.com` and `*cdn.onenote.net`.
- **Provider support:** Currently, only Microsoft Cloud endpoints are supported.
- **No granularity:** Currently, any of the 'allowed' endpoints will be added, with no options for granularity.

## Supported Cloud Providers

| Provider    | Status       | API Used |
|-------------|-------------|----------|
| Microsoft (Office 365, Entra ID, etc.) | ✅ Supported | [Microsoft Endpoint API](http://aka.ms/ipurlws) |

## Why Use This?

If you use **Little Snitch** on macOS and rely on cloud services, this script helps you:
- **Automate rule creation** for outbound network access.
- **Easily update** firewall rules when endpoints change.

## Prerequisites

- macOS with [Little Snitch](https://www.obdev.at/products/littlesnitch/index.html).
- Python 3.7+  
- Python package: `requests`  

Install dependencies:

```bash
pip install requests
```

## **Disclaimer**

This project is **not affiliated with, endorsed by, or associated with Objective Development** or **Little Snitch** in any way. Little Snitch is a product of [Objective Development Software GmbH](https://www.obdev.at).

**Use at Your Own Risk**
This script **should not be relied upon to reliably update your firewall rules** and should not be relied upon for security or compliance purposes. The generated rules are based on publicly available data but may be incomplete, outdated, or incorrect. **Users should manually verify all rules before applying them.**

**Self-Hosting Recommended**
If you intend to use these rules regularly, it is strongly recommended that you **host your own version** of this script or fork this repository to ensure control over updates.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
