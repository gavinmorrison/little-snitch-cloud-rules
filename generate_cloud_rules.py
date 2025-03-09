#!/usr/bin/env python3
"""
Little Snitch Cloud Rules Generator
-----------------------------------
This script fetches cloud service provider endpoint data and generates 
a .ov rule file formatted for Little Snitch on macOS.

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
import datetime
import logging
from typing import Any, Dict, List

# Configure logging for better observability in production
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# Microsoft API endpoint base URL
BASE_MS_API_URL = "https://endpoints.office.com/endpoints/worldwide"

# Output file name for the Little Snitch rule file
OUTPUT_FILE = "microsoft_cloud_rules.ov"

def fetch_microsoft_endpoints(timeout: int = 10) -> Any:
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

def extract_rules(endpoints: Any) -> List[Dict[str, Any]]:
    """
    Extract relevant rules for outbound client traffic from endpoint data.
    
    Args:
        endpoints: The endpoint data from the API.
        
    Returns:
        A list of dictionaries, each representing a rule.
    """
    logging.info("Extracting rules from endpoint data...")
    rules = []
    
    # If endpoints is not a list, try to get the list from a key (e.g. "values")
    if not isinstance(endpoints, list):
        logging.warning("Endpoint data is not a list. Attempting to extract rules from dictionary values.")
        endpoints = endpoints.get("values", [])
    
    for service in endpoints:
        # Process URLs if available
        for url in service.get("urls", []):
            rules.append({
                "action": "allow",  # Allow traffic to Microsoft services
                "process": "ANY",   # Any process accessing Microsoft services
                "remote-hosts": [url]
            })
            logging.info(f"Added rule for URL: {url}")
        
        # Process IP addresses if available
        for ip in service.get("ips", []):
            rules.append({
                "action": "allow",
                "process": "ANY",
                "remote-hosts": [ip]
            })
            logging.info(f"Added rule for IP: {ip}")

    logging.info("Rules extraction complete.")
    return rules

def generate_ov_file(rules: List[Dict[str, Any]], output_file: str = OUTPUT_FILE) -> None:
    """
    Generate the Little Snitch .ov rule file.
    
    Args:
        rules: A list of rules to be written into the file.
        output_file: The output filename.
    
    Raises:
        IOError: If writing to the file fails.
    """
    logging.info("Generating .ov rule file...")
    now = datetime.datetime.now()
    subscription = {
        "name": "Microsoft Cloud Access",
        "description": f"Allows outbound traffic to Microsoft Cloud services. Last updated: {now.strftime('%Y-%m-%d %H:%M:%S')}",
        "author": "Automated Script",
        "rules": rules
    }
    try:
        with open(output_file, "w") as file:
            json.dump(subscription, file, indent=4)
    except IOError as e:
        logging.error("Failed to write the rule file.")
        raise e

    file_path = os.path.join(os.getcwd(), output_file)
    logging.info(f"Little Snitch rule file generated: {file_path}")

def main() -> None:
    try:
        endpoints = fetch_microsoft_endpoints()
        rules = extract_rules(endpoints)
        generate_ov_file(rules)
        logging.info("Done! You can now subscribe to the generated .ov file in Little Snitch.")
    except Exception as e:
        logging.error(f"An error occurred: {e}")

if __name__ == "__main__":
    main()