# Little Snitch Cloud Rules

This repository provides a Python script that fetches endpoint data from cloud service providers (initially only Microsoft) and generates **[Little Snitch](https://www.obdev.at/products/littlesnitch/index.html)** rule files to allow or restrict outbound traffic.

## Overview

This script:
- **Fetches** official cloud service provider endpoint lists (currently Microsoft, future expansion possible).
- **Extracts** relevant URLs and IPs.
- **Generates** a `.ov` rule file formatted for **Little Snitch** on macOS.
- **Keeps network security under your control** by ensuring only **verified** cloud endpoints are allowed.

## Supported Cloud Providers

| Provider    | Status       | API Used |
|-------------|-------------|----------|
| Microsoft Cloud (Office 365, Entra ID etc.) | ✅ Supported | [Microsoft Endpoint API](https://endpoints.office.com) |

## Why Use This?

If you use **Little Snitch** on macOS and rely on cloud services, this script helps you:
- **Automate rule creation** for outbound network access.
- **Ensure only official cloud provider endpoints** are allowed.
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

⚠ **Use at Your Own Risk**  
This script **does not automatically update** firewall rules and should not be relied upon for security or compliance purposes. The generated rules are based on publicly available data but may be incomplete, outdated, or incorrect. **Users must manually verify all rules before applying them.**

⚠ **Self-Hosting Recommended**  
If you intend to use these rules regularly, it is strongly recommended that you **host your own version** of this script or fork this repository to ensure control over updates.