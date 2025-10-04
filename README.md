# FIND CREDS BODY
A Python tool to search for credentials / API keys directly inside the response body (HTML, JS, JSON, etc.) of a list of URLs. Unlike scanning URL strings only, this tool performs HTTP requests to each endpoint and extracts API key/credential patterns using regex.

### Features
• Detects popular API keys: Google, AWS, Stripe, Slack, SendGrid, Github, Gitlab, Telegram, JWT, Bearer Token, etc.

• Fetches response body with requests (HTTPS supported, ignoring SSL verification).

• Clean, grouped output saved to a file.

• Works seamlessly with waybackurls for historical endpoint hunting.

### Installation

```
   git clone https://github.com/AdnanApriliyansyahh/ApiFinder
   ```
```
   cd ApiFinder
   ```
 ```
   pip3 install -r requirements.txt
   ```

### Usage

1. Generate URL list using waybackurls

```
   cat subdomains.txt | waybackurls | tee way.txt
```

2. Scan for API keys inside response bodies

```
python3 main.py way.txt -o api_body_creds.txt
```
3. Output Example (api_body_creds.txt):

=== Google API Key ===
  Found: AIzaSyDxxxxxx
  URL:   https://example.com/app.js

=== AWS Access Key ===
  Found: AKIAIOSFODNN7EXAMPLE
  URL:   https://api.example.com/config.json

### Hunting Workflow

1. Gather subdomains → subfinder / assetfinder
2. Fetch historical endpoints → waybackurls
3. Extract credentials from responses → find_creds_body

### Full example:


```
subfinder -d example.com -silent | tee subs.txt
cat subs.txt | waybackurls | tee way.txt
python3 main.py way.txt -o api_body_creds.txt
```















   
