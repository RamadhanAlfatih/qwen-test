# Burp AI Helper

A command-line tool designed to streamline the workflow of web penetration testers and bug bounty hunters who use AI for vulnerability analysis. It formats raw HTTP requests/responses and JavaScript bundles into clean, structured Markdown prompts ready to be pasted into LLMs.

## Features

### 1. HTTP Request/Response Analysis (Interactive)
- Paste a raw HTTP request copied from Burp Suite.
- The tool executes the request against the target.
- Outputs a formatted block containing the **Original Request** and the **Live Response**.
- Ideal for analyzing specific interactions like authentication flows or injection points.

### 2. JavaScript Bundle Analysis
- Paste minified or beautified JavaScript code.
- **Automatic Secret Scanning**: Runs local regex checks to highlight potential hardcoded secrets (AWS keys, API tokens, JWTs, internal URLs) before sending to AI.
- Formats the code with syntax highlighting and suggests specific AI prompts (e.g., "Find hidden endpoints," "Analyze auth logic").

### 3. Batch Processing (New!)
- **Paste multiple requests at once**.
- Automatically detects boundaries between requests (e.g., `GET /...`, `POST /...`).
- Processes every request in the list sequentially.
- Generates a **single Markdown file** (`output_<timestamp>.md`) containing all request/response pairs.
- Perfect for dumping an entire Burp history log or a sequence of steps for a complex attack chain.

## Installation

Requires Python 3 and the `requests` library.

```bash
pip install requests
```

## Usage

Run the tool from your terminal:

```bash
python3 burp_ai_helper.py
```

### Workflow Examples

#### Scenario A: Analyzing a Single Request
1. Select **Mode 1**.
2. Copy a request from Burp's "Raw" tab.
3. Paste it into the terminal and type `END`.
4. Copy the generated Markdown output and paste it into your AI chat.

#### Scenario B: Analyzing a JS Bundle
1. Select **Mode 2**.
2. Paste the content of a `.js` file found in the browser sources.
3. The tool will print local findings (secrets/urls) immediately.
4. Copy the formatted code block to ask the AI about logic flaws.

#### Scenario C: Batch Processing History
1. Select **Mode 3**.
2. Copy a large chunk of text containing multiple HTTP requests from your notes or Burp history.
3. Paste it all at once and type `END`.
4. The tool will create a file named `output_YYYYMMDD_HHMMSS.md`.
5. Upload this file to your AI context or copy its contents.

## Output Format

The tool generates clean Markdown like this:

```markdown
### Request 1
**Method:** GET
**URL:** https://example.com/api/user

**Request:**
```http
GET /api/user HTTP/1.1
Host: example.com
...
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{"id": 1, "role": "admin"}
```
---
```

## Disclaimer

This tool is intended for educational purposes and authorized security testing only. 
- Only test systems you have permission to test.
- Do not use this tool to send malicious payloads to targets without explicit authorization.
- The "Batch Processing" mode will actively send requests to the target; ensure you understand the scope of your engagement before running large lists of requests.
