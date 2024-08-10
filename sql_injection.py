import argparse
import requests
import time
from termcolor import colored
import signal
import sys
import os
from urllib.parse import urlencode, parse_qs

### Signal Handling for Ctrl+C ###
def signal_handler(sig, frame):
    """Handle Ctrl+C signal and prompt the user to continue or exit."""
    response = input("\nAre you sure you want to stop the testing? [y/n]: ").strip().lower()
    if response == 'y':
        print(colored("Stopped by the user. Exiting...", "red",))
        sys.exit(0)
    else:
        print("Continuing testing...")

signal.signal(signal.SIGINT, signal_handler)

### Function to Read Payloads from a File ###
def read_payloads(file_path):
    try:
        with open(file_path, 'r') as file:
            payloads = [line.strip() for line in file.readlines()]
        return payloads
    except Exception as e:
        print(f"Error reading payload file: {e}")
        return []

### Function to Parse Raw HTTP Request ###
def parse_raw_request(file_path):
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()
            request_line = lines[0].strip()
            method, path, http_version = request_line.split()
            headers = {}
            body = None

            header_done = False
            for line in lines[1:]:
                if line == '\n':
                    header_done = True
                elif not header_done:
                    key, value = line.split(":", 1)
                    headers[key.strip()] = value.strip()
                else:
                    body = line.strip()

            return method, path, headers, body, http_version
    except Exception as e:
        print(f"Error parsing raw request file: {e}")
        return None, None, None, None, None

### Function to Construct Full URL ###
def construct_url(headers, path):
    """Construct the full URL from the Host header and path."""
    scheme = "https" if headers.get("Host", "").startswith("https") else "http"
    return f"{scheme}://{headers['Host']}{path}"

### Function to Send Requests with Payloads ###
def send_request(url, method, headers, body):
    """Send HTTP request with the provided parameters."""
    try:
        if method == "GET":
            response = requests.get(url, headers=headers)
        elif method == "POST":
            response = requests.post(url, headers=headers, data=body)
        else:
            return None

        return response
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return None

### Function to Test Injection in Headers ###
def test_headers(url, method, headers, body, payloads):
    """Test SQL injection by injecting payloads into each header value."""
    for header in headers:
        original_value = headers[header]
        for payload in payloads:
            # Inject payload into the current header
            headers[header] = original_value + payload
            
            start_time = time.time()
            response = send_request(url, method, headers.copy(), body)
            end_time = time.time()

            elapsed_time = end_time - start_time

            if elapsed_time > 5:  # assuming 5 seconds as the delay threshold
                timestamp = time.strftime("%H:%M:%S", time.localtime())
                print(colored(f"[{timestamp}] [✓ SUCCESS] : {header} -> {payload}", 'light_green'))
            else:
                timestamp = time.strftime("%H:%M:%S", time.localtime())
                print(colored(f"[{timestamp}] [✗ FAILED]  : {header} -> {payload}", 'dark_grey'))
        
        # Reset the header to its original value
        headers[header] = original_value

### Function to Test Injection in Body Parameters ###
def test_body_parameters(url, method, headers, body, payloads):
    """Test SQL injection by injecting payloads into each body parameter."""
    params = parse_qs(body)
    for param in params:
        original_value = params[param][0]
        for payload in payloads:
            # Inject payload into the current parameter
            params[param] = [original_value + payload]
            modified_body = urlencode(params, doseq=True)
            
            start_time = time.time()
            response = send_request(url, method, headers, modified_body)
            end_time = time.time()

            elapsed_time = end_time - start_time

            if elapsed_time > 5:  # assuming 5 seconds as the delay threshold
                timestamp = time.strftime("%H:%M:%S", time.localtime())
                print(colored(f"[{timestamp}] [✓ SUCCESS] : {param} -> {payload}", 'light_green'))
            else:
                timestamp = time.strftime("%H:%M:%S", time.localtime())
                print(colored(f"[{timestamp}] [✗ FAILED]  : {param} -> {payload}", 'dark_grey'))

### Function to Test Injection in URL Parameters ###
def test_url_parameters(url, headers, payloads):
    """Test SQL injection by injecting payloads into URL parameters."""
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    for param in query_params:
        original_value = query_params[param][0]
        for payload in payloads:
            # Inject payload into the current URL parameter
            query_params[param] = [original_value + payload]
            modified_query = urlencode(query_params, doseq=True)
            modified_url = urlunparse(parsed_url._replace(query=modified_query))

            start_time = time.time()
            response = send_request(modified_url, "GET", headers, None)
            end_time = time.time()

            elapsed_time = end_time - start_time

            if elapsed_time > 5:  # assuming 5 seconds as the delay threshold
                timestamp = time.strftime("%H:%M:%S", time.localtime())
                print(colored(f"[{timestamp}] [✓ SUCCESS] : {param} -> {payload}", 'light_green'))
            else:
                timestamp = time.strftime("%H:%M:%S", time.localtime())
                print(colored(f"[{timestamp}] [✗ FAILED]  : {param} -> {payload}", 'dark_grey'))

### Main Function for Testing SQL Injections ###
def main():
    parser = argparse.ArgumentParser(description="A tool for testing SQL injections using payloads from a file")
    parser.add_argument('-u', '--url', type=str, help='Target URL')
    parser.add_argument('-r', '--request', type=str, help='File path to the raw HTTP request')
    parser.add_argument('-p', '--payloads', type=str, help='Custom file path to the payloads file')

    args = parser.parse_args()

    # Set the payload file path, default to 'payloads.txt' in the current directory
    payload_file = args.payloads if args.payloads else os.path.join(os.path.dirname(__file__), 'payloads.txt')

    payloads = read_payloads(payload_file)

    if not payloads:
        print("No payloads found or error reading the payloads file.")
        return

    if args.request:
        # Handle raw HTTP request file
        method, path, headers, body, http_version = parse_raw_request(args.request)
        if not method or not path or not headers or not http_version:
            print("Error: Could not parse the raw request file.")
            return
        url = construct_url(headers, path)

        # Test SQL injection in headers
        test_headers(url, method, headers, body, payloads)

        # Test SQL injection in body parameters if it's a POST request
        if method == "POST" and body:
            test_body_parameters(url, method, headers, body, payloads)

    elif args.url:
        # Handle direct URL
        url = args.url
        headers = {}

        # Test SQL injection in URL parameters
        test_url_parameters(url, headers, payloads)

    else:
        print("Error: You must provide either a URL (-u) or a raw request file (-r).")
        return

if __name__ == "__main__":
    main()
