#!/usr/bin/env python3
"""
Little Snitch Cloud Rules Generator
-----------------------------------
This script fetches cloud service provider endpoint data and generates
a .lsrules rule file formatted for Little Snitch on macOS.

https://help.obdev.at/littlesnitch4/lsc-rule-group-subscriptions

GitHub Repository: https://github.com/gavinmorrison/little-snitch-cloud-rules
Author: Gavin Morrison
License: MIT
Requires: Python 3.7+, requests

Disclaimer:
This project is NOT affiliated with Objective Development or Little Snitch.
Users are responsible for verifying and applying the generated rules manually.
"""

import json
import requests
import uuid
import os
import logging
from typing import Any, Dict, List

# Configure logging for better observability in production
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# Configuration settings
ADD_PORT_RULES = True
OUTPUT_DIR = "rules"
BASE_MS_API_URL = "https://endpoints.office.com/endpoints/worldwide"

# Ensure the output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

def fetch_microsoft_endpoints(timeout: int = 10) -> Dict[str, Any]:
    """
    Fetch the latest Microsoft endpoint data from the API with a unique client request id.

    Args:
        timeout (int): Timeout in seconds for the API request.

    Returns:
        The JSON data returned by the API.

    Raises:
        requests.exceptions.RequestException: If the HTTP request fails.
        ValueError: If the response cannot be parsed as JSON.
    """
    client_request_id = uuid.uuid4()  # Generate a unique ID for each request
    api_url = f"{BASE_MS_API_URL}?clientrequestid={client_request_id}"
    logging.info("Sending request to Microsoft API...")

    try:
        response = requests.get(api_url, timeout=timeout)
        response.raise_for_status()  # Raises HTTPError for bad responses
    except requests.exceptions.RequestException as e:
        logging.error("Request to Microsoft API failed.")
        raise e

    try:
        data = response.json()
    except ValueError as e:
        logging.error("Response content is not valid JSON.")
        raise e

    logging.info("Successfully fetched Microsoft endpoint data.")
    return data

def build_notes(service: Dict[str, Any]) -> str:
    """
    Build a notes string from the service metadata, excluding hosts and IPs.
    """
    notes_parts = [
        f"id: {service['id']}" if "id" in service else None,
        f"serviceArea: {service['serviceArea']}" if "serviceArea" in service else None,
        f"serviceAreaDisplayName: {service['serviceAreaDisplayName']}" if "serviceAreaDisplayName" in service else None,
        f"tcpPorts: {service['tcpPorts']}" if "tcpPorts" in service and service["tcpPorts"] else None,
        f"udpPorts: {service['udpPorts']}" if "udpPorts" in service and service["udpPorts"] else None,
        f"category: {service['category']}" if "category" in service else None,
        f"expressRoute: {service['expressRoute']}" if "expressRoute" in service else None,
        f"required: {service['required']}" if "required" in service else None,
        f"notes: {service['notes']}" if "notes" in service and service["notes"] else None,
    ]

    return "\n".join(filter(None, notes_parts))

def create_rule(service, key, value, notes, protocol=None, ports=None):
    """
    Create a rule dictionary with optional protocol and ports.
    """
    rule = {
        "action": "allow",
        "process": "ANY",
        key: value,
        "notes": notes
    }
    if protocol and ports:
        rule.update({"protocol": protocol, "ports": ports.strip()})
    return rule

def extract_rules(endpoints: Any) -> List[Dict[str, Any]]:
    """
    Extract relevant rules for outbound client traffic from endpoint data,
    appending detailed metadata in the "notes" field.

    Args:
        endpoints: The endpoint data from the API.

    Returns:
        A list of dictionaries, each representing a rule.
    """
    logging.info("Extracting rules from endpoint data...")
    rules = []

    if not isinstance(endpoints, list):
        logging.warning("Endpoint data is not a list. Attempting to extract rules from dictionary values.")
        endpoints = endpoints.get("values", [])

    for service in endpoints:
        notes = build_notes(service)

        for url in service.get("urls", []):
            if "*" in url:
                # Valid wildcard: must start with "*." and only contain one "*" character.
                if url.startswith("*.") and url.count("*") == 1:
                    key = "remote-domains"
                    value = [url[2:]]  # Remove the "*." part.
                else:
                    # 🚨 Warning: Non-standard wildcard found, so we skip this rule.
                    logging.warning(f"🚨 Non-standard wildcard domain encountered: {url}. This rule will be skipped.")
                    continue
            else:
                key = "remote-hosts"
                value = [url]

            if ADD_PORT_RULES:
                if service.get("tcpPorts"):
                    rules.append(create_rule(service, key, value, notes, protocol="tcp", ports=service["tcpPorts"]))
                if service.get("udpPorts"):
                    rules.append(create_rule(service, key, value, notes, protocol="udp", ports=service["udpPorts"]))
                if not service.get("tcpPorts") and not service.get("udpPorts"):
                    rules.append(create_rule(service, key, value, notes))
            else:
                rules.append(create_rule(service, key, value, notes))

        for ip in service.get("ips", []):
            if ADD_PORT_RULES:
                if service.get("tcpPorts"):
                    rules.append(create_rule(service, "remote-addresses", [ip], notes, protocol="tcp", ports=service["tcpPorts"]))
                if service.get("udpPorts"):
                    rules.append(create_rule(service, "remote-addresses", [ip], notes, protocol="udp", ports=service["udpPorts"]))
                if not service.get("tcpPorts") and not service.get("udpPorts"):
                    rules.append(create_rule(service, "remote-addresses", [ip], notes))
            else:
                rules.append(create_rule(service, "remote-addresses", [ip], notes))

    logging.info("Rules extraction complete.")
    return rules

def generate_ov_file(rules: List[Dict[str, Any]], provider: str = "microsoft") -> None:
    """
    Generate the Little Snitch .lsrules rule file and save it in the rules/ directory.

    Args:
        rules: A list of rules to be written into the file.
        provider: The cloud provider name (used for naming the file).

    Raises:
        IOError: If writing to the file fails.
    """
    logging.info(f"Generating .lsrules rule file for {provider}...")

    filename = f"cloud_rules_{provider}.lsrules"
    file_path = os.path.join(OUTPUT_DIR, filename)

    subscription = {
        "name": f"{provider.capitalize()} Cloud Access",
        "description": f"Allows outbound traffic to {provider.capitalize()} Cloud services.",
        "author": "Automated Script",
        "rules": rules
    }

    try:
        with open(file_path, "w") as file:
            json.dump(subscription, file, indent=4)
    except IOError as e:
        logging.error(f"Failed to write the rule file for {provider}.")
        raise e

    logging.info(f"Little Snitch rule file generated: {file_path}")

def main() -> None:
    try:
        endpoints = fetch_microsoft_endpoints()
        rules = extract_rules(endpoints)
        generate_ov_file(rules, provider="microsoft")
        logging.info("Done! You can now subscribe to the generated .lsrules file in Little Snitch.")
    except Exception as e:
        logging.error(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
