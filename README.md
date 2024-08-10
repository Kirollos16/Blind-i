## BLIND-I is simple and unique tool for testing Time-based SQL injection
This tool is designed to automate the process of testing Time-based SQL injection vulnerabilities in both web *URLs* and raw *HTTP requests*. It can inject various payloads into URL parameters, HTTP headers, and POST request bodies, allowing security professionals to quickly identify potential vulnerabilities in web applications.

## Features

- **URL Testing:** Injects SQL payloads into URL parameters and analyzes the response for potential vulnerabilities.
- **Raw HTTP Request Testing:** Injects SQL payloads into HTTP headers and POST request body parameters.
- **Supports GET and POST Methods:** Can handle both GET and POST requests with ease.
- **Custom Payloads:** Allows you to define your own payloads through a text file.
- **Color-Coded Output:** Successful injections are highlighted in green, and failed attempts are marked in red.
  
## Requirements

- Python3
- You can install all requirements with `pip install -r requirements.txt`

## Installation
1. **Clone the repository:**

   ```bash
   git clone https://github.com/Kirollos16/Blind-i.git
   cd Blind-i
   ```

## Usage
This tool is very simple to use

To test a URL:
```python3 Blind-i.py -u "http://example.com/vulnerable?param=1"```

Testing a Raw HTTP Request:
```python3 Blind-i.py -r request.txt```

Using Custom Payloads:
```python3 Blind-i.py -u "http://example.com/vulnerable?param=1" -p custom_payloads.txt```
