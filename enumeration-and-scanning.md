# Enumeration & Scanning

**Enumeration & Scanning**

* Asset → FLinks → HTTPX → Nuclei (Open Redirect)
* Asset → HTTPX → CORS Misconfiguration
* Assets → Backup Fuzzer → Information Disclosure
* Assets → FLinks → HTTPx → XSS Detector
* Fuzzing on various properties



## <mark style="background-color:red;">Open Redirect</mark>

An open redirect vulnerability occurs when a web application accepts user-supplied input to redirect the user to another website. This can be exploited by an attacker to redirect users to malicious websites, phishing sites, or other unwanted destinations.

1. **Information Gathering:**
   * Use web scraping tools like Scrapy, BeautifulSoup, or Selenium to gather information about the target website.
   * Use domain analysis tools like Domain Hunter Plus, Domain Hunter, or Buer to find subdomains and associated IP addresses.
   * Use OSINT tools like Maltego, Recon-ng, or theHarvester to gather information from public sources.
2. **Spidering and Crawling:**
   * Use web crawlers like Scrapy, SpiderFoot, or Burp Suite's Spider to map out the website's structure and find potential targets.
   * Use directory brute-forcing tools like DirBuster or Gobuster to find hidden directories and endpoints.
3. **Fuzzing:**
   * Use fuzzing tools like Burp Suite's Intruder, ffuf, or OWASP ZAP to test for Open Redirect vulnerabilities.
   * Use payloads like `http://example.com/redirect?url=http://evil.com`, `javascript:alert(1)`, or `data:text/html,<script>alert(1)</script>` to test for Open Redirect vulnerabilities.
4. **Manual Testing:**
   * Manually test forms, links, and other user input fields for Open Redirect vulnerabilities.
   * Check for the use of redirect functions in the website's source code.
5. **Automated Testing:**
   * Use automated tools like DotDotPenTest, NoSQLMap, or sqlmap to test for Open Redirect vulnerabilities.
   * Use tools like OWASP ZAP, Burp Suite, or Nikto to perform automated scans for Open Redirect vulnerabilities.

Here's a simple Python script that can be used to test for Open Redirect vulnerabilities:

```python
import requests

def test_open_redirect(url):
    test_url = f"{url}?url=http://evil.com"
    response = requests.get(test_url)
    if "http://evil.com" in response.url:
        print(f"Open Redirect vulnerability found at {url}")
    else:
        print(f"No Open Redirect vulnerability found at {url}")

test_open_redirect("http://example.com/redirect")
```

This script sends a GET request to the target URL with a malicious parameter, and checks if the response URL contains the malicious domain.

Commonly Used Tools:

* **Burp Suite**
* **OWASP ZAP** (Zed Attack Proxy)
* **Scrapy** - `scrapy crawl your_spider_name -a start_url='http://target.com/' -o items.json`
* **BeautifulSoup**
*   **Requests** (Python library) - `requests.get('http://target.com/', allow_redirects=True)`

    This command sends a GET request to the target URL using the `requests` library, with the `allow_redirects` parameter set to `True` to follow any redirects.
*   **Google Dorks** - `site:http://target.com/ inurl:redirect`

    This command uses Google Dorks to search for pages on the target website that contain the word "redirect".
*   **DirBuster** - `dirb http://target.com/ -r`

    This command uses DirBuster to scan the target URL for directories and follow any redirects. The `-r` option tells DirBuster to recurse through directories.
*   **Gobuster** - `gobuster dir -u http://target.com/ -r`

    This command uses Gobuster to scan the target URL for directories and follow any redirects. The `-u` option specifies the URL to scan and the `-r` option tells Gobuster to recurse through directories.
* **Maltego**
*   **Recon-ng** - `recon-ng -r http://target.com/`

    This command uses Recon-ng to perform a reconnaissance scan of the target URL and follow any redirects.
*   **theHarvester** - `theharvester -p http://target.com/`

    This command uses theHarvester to perform a reconnaissance scan of the target URL and follow any redirects.
*   **NoSQLMap** - `nosqlmap -u http://target.com/`

    This command uses NoSQLMap to perform a reconnaissance scan of the target URL and follow any redirects.
*   **Nikto** - `nikto -host http://target.com/`

    This command uses Nikto to perform a reconnaissance scan of the target URL and follow any redirects.
* **Ffuf** - `ffuf -u https://example.com/FUZZ -w /path/to/wordlist -mc 302`\
  Ffuf is a fast web fuzzer that can be used to find Open Redirect vulnerabilities. It can be customized to look for redirects based on specific patterns or status codes.
* **Gospider** - `gospider -u https://example.com -c 50 -s "https?://.*.(com|org|net)" | tee output.txt`\
  Gospider is a web crawler that can be used to automatically crawl the application and identify potential Open Redirect vulnerabilities. It can be configured to follow redirects and look for changes in the URL.
* **Hakrawler** - `hakrawler -u https://example.com -depth 3 -linkfinder -insecure`\
  Hakrawler is another web crawler that can be used to automatically crawl the application and identify potential Open Redirect vulnerabilities. It can be configured to follow redirects and look for changes in the URL.
* **Nuclei** - `nuclei -t /path/to/nuclei-templates/http/vulnerabilities/open-redirect.yaml -u https://example.com`\
  Nuclei is a fast and customizable vulnerability scanner that can be used to find Open Redirect vulnerabilities. It has a template specifically designed for Open Redirect checks.
* **Dirsearch** - `dirsearch -u https://example.com -e *` \
  Dirsearch is a directory/file enumeration tool that can be used to find Open Redirect vulnerabilities. It can be customized to look for redirects based on specific patterns or status codes.

also, you can use Linux-built tools like `curl, lynx, curl, wget`



Example Python Script:

```python
import requests

def test_open_redirect(url, parameter):
    payload = {"redirect": "http://evil.com"}
    response = requests.get(url, params={parameter: payload})
    if response.history:
        print(f"Potential open redirect found at: {url}")
        for resp in response.history:
            print(f"Redirected to: {resp.url}")
    else:
        print(f"No open redirect found at: {url}")

# Example usage
test_open_redirect("https://example.com", "return_url")
```



Example Python Script:

```python
import requests
import re

def find_open_redirect(url):
    try:
        response = requests.get(url, allow_redirects=False)
        if response.status_code == 302 or response.status_code == 301:
            redirect_url = response.headers.get('Location')
            if redirect_url:
                if not re.match(r'^https?://', redirect_url):
                    return redirect_url
    except:
        pass
    return None

# Example usage
url = 'https://example.com'
redirect_url = find_open_redirect(url)
if redirect_url:
    print(f"Open Redirect found: {redirect_url}")
else:
    print("No Open Redirect vulnerability found.")
```



Example Python Script:

```python
import re
import requests

def find_open_redirects(target_url):
    # Make a GET request to the target URL
response = requests.get(target_url)
    content = response.content.decode('utf-8')

    # Extract URLs from the response content using regex
urls = re.findall(r'https?://[^"\'<>]+', content)

    # Check each extracted URL for open redirect vulnerability
for url in urls:
        # Construct the test URL by adding a unique identifier and a redirect parameter
test_url = f"{url}?redirect_test=unique_string"
# Send a GET request to the test URL
redirect_response = requests.get(test_url, allow_redirects=True)

        # Check if the redirect location contains the unique identifier, indicating a potential open redirect vulnerability
if 'unique_string' in redirect_response.url:
            print(f"Open redirect vulnerability found: {url}")

# Set the target URL you want to test
target_url = "https://example.com"
find_open_redirects(target_url)

```



### At the end of this topic you can consider this flow to start to find an Open Redirect vulnerability: 

1\. **URL Manipulation**:

* Modify the URL to redirect to an external domain, for example, change `https://example.com/redirect?url=https://example.com/page` to `https://example.com/redirect?url=https://malicious-site.com`
* If the application redirects to `https://malicious-site.com` without proper validation, it might be vulnerable to Open Redirect.

2\. **Form Submissions**:

* Find a form that allows users to specify a URL, such as a login form with a "return URL" parameter.
* Submit the form with a user-supplied URL, for example, `return_url=https://malicious-site.com`.
* If the application redirects to `https://malicious-site.com` without proper validation, it might be vulnerable to Open Redirect.

3\. **Link Clicks**:

* Find a link or button that redirects to a user-supplied URL, such as a "Share on social media" button.
* Click on the link or button and observe if the application redirects to an external domain without proper validation.

4\. **Edge Cases**:

* Test URLs with special characters, encoded URLs, or malformed URLs.
* Check for redirects to empty or null URLs, for example, `https://example.com/redirect?url=`
* If the application redirects to unexpected or invalid URLs, it might indicate poor input validation and potential Open Redirect vulnerability.

5\. **Bypassing Validation**:

* Attempt to bypass any validation in place by manipulating the URL, for example, encoding the URL or using special characters.
* If the application fails to validate the URL properly, it might be vulnerable to Open Redirect.

6\. **Fuzzing and Brute-Forcing**:

* Use tools like Dirsearch or Ffuf to enumerate URLs, subdomains, and parameters.
* Fuzz the URLs and parameters to find potential redirects.
* Test for common and predictable URLs, such as /redirect, /forward, or /url.

### <mark style="color:red;">Asset → FLinks → HTTPX → Nuclei (Open Redirect)</mark>

1. **Asset Discovery**:
   * This is the first step in the process, where you identify the target asset or application that you will be testing for open redirect vulnerabilities. The asset could be a website, web application, or any other type of application that accepts user input and processes it in some way.
   * The first step is to identify the assets or web applications that need to be tested.
   * Tools like `assetfinder` or `subfinder` can be used to discover subdomains and other assets related to the target.
   * The first step is to identify the target asset, which in this case is the web application. You would start by exploring the application and identifying any links or URLs that could be tested for open redirect vulnerabilities.
2. **FLinks**:
   * This step involves using a tool or technique to discover any external links or URLs within the target asset. These links could potentially be used to identify open redirect vulnerabilities.
   * FLinks is a tool that can be used to extract hyperlinks from the discovered assets.
   * It inputs a list of assets and generates a file with all the extracted links.
   * if you couldn't find Flinks try using this command (`httpx -o assets-httpx -sc 404,403,401,500 https:// # Replace with the actual URL nuclei -t open-redirect.yaml assets-httpx`)
   * Once you have identified some potential targets, you would use a tool like FLinks to discover any external links or URLs that are present within the application. These links could potentially be used to identify open redirect vulnerabilities.
3. **HTTPX**:
   * HTTPX is a fast and feature-rich HTTP client that can be used to check the status of the links extracted by FLinks.
   * It filters out the non-200 status codes (e.g., 404, 403, 401, 500) to focus on the potentially valid endpoints.
   * After you have identified some external links or URLs, you would use HTTPX to test each one for open redirect vulnerabilities. You would do this by manipulating the URL parameters and observing the response. For example, you might try changing the URL parameter that specifies the destination URL to a different domain and observing whether the application redirects you to that domain.
4. **Nuclei**:
   * Nuclei is a powerful vulnerability scanning tool that can be used to identify open redirect vulnerabilities in tested web applications.
   * It uses a template-based approach, allowing easy customization and integration of new vulnerability checks.
   * Finally, you would use Nuclei with the "Open Redirect" template to automate the process of testing for open redirect vulnerabilities. The template would generate requests and analyze responses for signs of open redirect vulnerabilities. If any vulnerabilities are found, Nuclei will report them to you.
5. **Open Redirect Vulnerability Testing**:
   * The provided Nuclei template targets the top 25 parameters commonly used for open redirect vulnerabilities.
   * It checks for the presence of a `Location` header in the response, which could indicate a redirect to an external website.
   * The template also checks for specific HTTP status codes (301, 302, 307, 308) that are often associated with open redirect vulnerabilities.

<mark style="background-color:orange;">Tip</mark>: FLinks is not a well-known or commonly used tool for discovering external links or URLs within a web application. Instead, you can use other tools or techniques to achieve the same goal. You can use a web spidering tool like Screaming Frog or Sitebulb to crawl the web application and identify all of the links and URLs within it. These tools can help you identify external links or URLs that could be used to test for open redirect vulnerabilities.

Instead, you can use this command as an example:

{% code overflow="wrap" %}
```sql
ffuf -w /usr/share/wordlists/wfuzz/general/admin-panels.txt -u https://example.com/FUZZ -t 100 | httpx - | tee assets-httpx | nuclei -t /path/to/nuclei-templates/http/vulnerabilities/wordpress/wp-security-open-redirect.yaml

```
{% endcode %}



Here's an example of a vulnerable code snippet:

```php
<?php
// Vulnerable code example
$redirectUrl = $_GET['url'];
header("Location: " . $redirectUrl);
?>
```

In this example, the application takes the `url` parameter from the URL and redirects the user to the specified URL without any validation. An attacker could potentially craft a URL like `https://vulnerable-website.com/redirect?url=https://malicious-website.com`, which would redirect the user to the malicious website without any warning.



Open Redirect Nuclei template Top 25 Parameters:

{% code overflow="wrap" %}
```yaml
id: open-redirectinfo:
name: Open URL redirect detection
author: Vizir
severity: low
description: A user-controlled input redirects users to an external website.
tags: redirect,generic

requests:
  - method: GET
    path:
      - "{{BaseURL}}/?next=https://example.com&url=https://example.com&target=https://example.com&rurl=https://example.com&dest=https://example.com&destination=https://example.com&redir=https://example.com&redirect_uri=https://example.com&redirect_url=https://example.com&redirect=https://example.com&view=https://example.com&image_url=https://example.com&go=https://example.com&return=https://example.com&returnTo=https://example.com&return_to=https://example.com&checkout_url=https://example.com&continue=https://example.com&return_path=https://example.com"
    matchers-condition: and
    matchers:
      - type: regex
        part: header
        regex:
          - '(?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]*)example\.com\/?(\/|[^.].*)?$'
      - type: status
        status:
          - 301
          - 302
          - 307
          - 308
        condition: or
```
{% endcode %}

* `id`: A unique identifier for the template.
* `name`: The name of the template.
* `author`: The author of the template.
* `severity`: The severity level assigned to the template.
* `description`: A brief description of the vulnerability being detected.
* `tags`: Tags associated with the template, such as "redirect" and "generic".
* `requests`: An array specifying the requests to be sent to the target URL.
  * `method`: The HTTP method used for the request (in this case, `GET`).
  * `path`: An array of URL paths to send the request to. The template includes various parameters (`next`, `url`, `target`, etc.) with example URLs set to `https://example.com`.
  * `matchers-condition`: Specify the condition for the matchers to be checked. In this case, `and` this means all matchers must match.
  * `matchers`: An array of matchers used to validate the response.
    * The first matcher is a `regex` matcher that checks the `Location` header of the response. It looks for URLs matching the specified pattern, which is included `example.com` in the path.
    * The second matcher is a `status` matcher that checks the HTTP status code of the response. It matches any of the specified status codes (`301`, `302`, `307`, `308`) to indicate a redirect.

This template is designed to be generic and can be used to scan a wide range of web applications for potential open redirect vulnerabilities. By sending requests with various parameters and analyzing the response headers, the template detects instances where user-controlled input is redirected to an external website without proper validation.



Refined Version of the above YAML code

```yaml
id: open-redirect
info:
name: Open URL redirect detection
author: Vizir
severity: low
description: A user-controlled input redirects users to an external website.
tags: redirect, generic
requests:
- method: GET
path:
- "{{BaseURL}}/?next={{ExternalDomain}}"
- "{{BaseURL}}/?url={{ExternalDomain}}"
- "{{BaseURL}}/?target={{ExternalDomain}}"
- "{{BaseURL}}/?rurl={{ExternalDomain}}"
- "{{BaseURL}}/?dest={{ExternalDomain}}"
- "{{BaseURL}}/?destination={{ExternalDomain}}"
- "{{BaseURL}}/?redir={{ExternalDomain}}"
- "{{BaseURL}}/?redirect_uri={{ExternalDomain}}"
- "{{BaseURL}}/?redirect_url={{ExternalDomain}}"
- "{{BaseURL}}/?redirect={{ExternalDomain}}"
- "{{BaseURL}}/?view={{ExternalDomain}}"
- "{{BaseURL}}/?image_url={{ExternalDomain}}"
- "{{BaseURL}}/?go={{ExternalDomain}}"
- "{{BaseURL}}/?return={{ExternalDomain}}"
- "{{BaseURL}}/?returnTo={{ExternalDomain}}"
- "{{BaseURL}}/?return_to={{ExternalDomain}}"
- "{{BaseURL}}/?checkout_url={{ExternalDomain}}"
- "{{BaseURL}}/?continue={{ExternalDomain}}"
- "{{BaseURL}}/?return_path={{ExternalDomain}}"
matchers-condition: and
matchers:
- type: regex
part: header
regex:
- '(?i)^(?:location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]*)example\.com\/?(\/|[^.].*)?$'
- type: status
status:
- 301
- 302
- 307
- 308
condition: or

```

* In this `requests.path` section, we use the `{{ExternalDomain}}` placeholder to represent the external domain that the user is redirected to. This way, you can test each path by replacing the `{{ExternalDomain}}` placeholder with a domain you want to test, such as `https://malicious-site.com`
* The regex in the `matchers` section has been updated to include the `(?i)` flag at the beginning, which makes the regex case-insensitive. This helps to match both uppercase and lowercase versions of `example.com`. The regex has also been modified to account for more possible variations of the redirection location format.

### Bypass Templates

1. **Bypass Techniques for Open Redirect Vulnerabilities**:
   * **Prepending the Redirect URL with `@`**: Some applications may not properly validate the redirect URL when it is prepended with the `@` symbol. For example: `https://target.com/?redirect=@example.com`.
   * **Using `//example.com` Syntax**: Some applications may not properly validate the redirect URL when it uses the `//example.com` syntax instead of the full `https://example.com` format. For example: `https://target.com/?redirect=//example.com`.
   * **Using URL Encoding/Double URL Encoding**: Encoding the redirect URL using URL encoding or double URL encoding can sometimes bypass the validation checks. For example: `https://target.com/?redirect=https%3A%2F%2Fexample.com` or `https://target.com/?redirect=https%3A%2F%2Fexample.com%2F`.
   * **Using Alternative Domains**: Instead of using `example.com`, try using alternative domains like `example.net`, `example.org`, or even subdomains like `subdomain.example.com`.
   * **Leveraging Unicode Characters**: Some applications may not properly handle Unicode characters in the redirect URL. For example: `https://target.com/?redirect=https://éxâmple.com`.
   * **Utilizing URL Shorteners**: Try using URL shortening services like `bit.ly`, `tinyurl.com`, or `shorturl.at` to obfuscate the redirect URL.
2. **Enhancing the Nuclei Template**:
   * **Customizing the Parameter List**: Expand the list of common parameters used for open redirect vulnerabilities. You can find more parameters by studying the target application's behavior and observing how it handles different types of redirect URLs.
   * **Implementing Recursive Checks**: Modify the template to recursively check the redirect URLs, as some applications may chain multiple redirects.
   * **Adding Payload Variations**: Incorporate different types of payloads, such as the bypass techniques mentioned earlier, to increase the chances of finding vulnerabilities.
   * **Conditional Matching**: Enhance the matcher conditions to include more specific checks, such as looking for the presence of the redirect URL in the response body or other parts of the response.
   * **Leveraging Wordlists**: Use custom wordlists or existing resources like the SecLists project to test a wider range of potential parameters and payloads.
3. **Necessary Knowledge and Tools**:
   * Strong understanding of web application security concepts, including open redirect vulnerabilities and common bypass techniques.
   * Familiarity with the Nuclei templating syntax and its capabilities for customizing vulnerability checks.
   * Knowledge of URL encoding, Unicode character handling, and other techniques for bypassing input validation.
   * Proficiency in using web application security testing tools, such as Burp Suite, OWASP ZAP, and custom scripts.
   * Ability to analyze and interpret the output of the Nuclei scanner to identify potential vulnerabilities.
4. **Recommendations**:
   * Continuously expand your knowledge of open redirect vulnerabilities and stay up-to-date with the latest trends and techniques.
   * Actively participate in bug bounty programs and collaborate with the security community to gain practical experience.
   * Develop a comprehensive testing methodology that includes both automated scanning and manual analysis.
   * Document your findings, report any vulnerabilities responsibly, and follow the appropriate disclosure process.
   * Seek feedback and collaborate with other security professionals to improve your skills and techniques.



## <mark style="background-color:red;">CORS Misconfiguration</mark>

CORS (Cross-Origin Resource Sharing) Misconfiguration is a common vulnerability found in web applications that can lead to unauthorized access and data theft. It occurs when the application fails to properly configure the CORS headers, allowing unauthorized external domains to access the application's resources.

Here are some ways to find CORS Misconfiguration in bug bounty:

1. **Manual Testing**:
   * Test all endpoints of the application by sending requests from different domains and check for any unexpected behavior.
   * Check the HTTP response headers for the presence of `Access-Control-Allow-Origin`, `Access-Control-Allow-Methods`, `Access-Control-Allow-Headers`, and `Access-Control-Allow-Credentials` headers.
   * If any of these headers are missing or misconfigured, it could indicate a CORS misconfiguration vulnerability.
2. **Automated Testing**:
   * Use tools like Burp Suite or OWASP ZAP to scan the application for CORS misconfiguration vulnerabilities.
   * These tools can detect and report on any CORS misconfiguration issues.
3. **Fuzzing**:
   * Fuzz the application's endpoints with different values for the `Origin` header to see if it allows unauthorized domains.
   * Look for responses with a status code of 200 or 204 (which could indicate successful CORS requests) when the `Origin` the header is set to a malicious domain.
4. **Source Code Review**:
   * Review the application's source code to look for any CORS configuration settings.
   * Check if the application sets the appropriate CORS headers for all endpoints.
   * Look for any configuration options that allow requests from all domains (`*`) or specific domains.
5. **API Documentation**:
   * Check the application's API documentation for any mentions of CORS configuration.
   * If the documentation does not specify the allowed origins, it could indicate a CORS misconfiguration issue.



### Here are some signs of CORS Misconfiguration:

1. **Incorrect or missing CORS headers**:
   * The application does not include the `Access-Control-Allow-Origin` header in its responses, allowing any domain to access the resources.
   * The application sets the `Access-Control-Allow-Origin` header to `*` or a specific domain, allowing any domain to access the resources.
   * The application does not include the `Access-Control-Allow-Methods`, `Access-Control-Allow-Headers`, or `Access-Control-Allow-Credentials` headers, allowing any method, header, or credentials to be used.
2. **Vulnerable to CSRF (Cross-Site Request Forgery) attacks**:
   * If the application does not properly implement CSRF protection, it can be vulnerable to CSRF attacks.
   * An attacker could send a malicious request from a trusted domain to the application, potentially compromising user sessions or performing unauthorized actions.
3. **Leaking sensitive information**:
   * If the application allows cross-origin requests, it may leak sensitive data, such as session tokens or authentication credentials, to external domains.
   * This can allow an attacker to steal user information or perform actions on the user's behalf.

To find CORS Misconfiguration vulnerabilities, you can use various techniques, such as:

1. **Manual testing**:
   * Test all endpoints of the application by sending requests from different domains and check for any unexpected behavior.
   * Check the HTTP response headers for the presence of `Access-Control-Allow-Origin`, `Access-Control-Allow-Methods`, `Access-Control-Allow-Headers`, and `Access-Control-Allow-Credentials` headers.
   * If any of these headers are missing or misconfigured, it could indicate a CORS misconfiguration vulnerability.
2. **Automated testing**:
   * Use tools like Burp Suite or OWASP ZAP to scan the application for CORS misconfiguration vulnerabilities.
   * These tools can detect and report on any CORS misconfiguration issues.
3. **Fuzzing**:
   * Fuzz the application's endpoints with different values for the `Origin` header to see if it allows unauthorized domains.
   * Look for responses with a status code of 200 or 204 (which could indicate successful CORS requests) when the `Origin` header is set to a malicious domain.
4. **Source code review**:
   * Review the application's source code to look for any CORS configuration settings.
   * Check if the application sets the appropriate CORS headers for all endpoints.
   * Look for any configuration options that allow requests from all domains (`*`) or specific domains.
5. **API documentation review**:
   * Check the application's API documentation for any mentions of CORS configuration.
   * If the documentation does not specify the allowed origins, it could indicate a CORS misconfiguration issue.

Here's an example of a CORS misconfiguration vulnerability that can be found using Burp Suite:

Request:

```
POST /api/login HTTP/1.1
Host: vulnerable-website.com
Origin: https://malicious-website.com
Content-Type: application/json

{"username": "admin", "password": "password"}
```

Response:

```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
Content-Type: application/json

{"success": true, "message": "Login successful"}
```

In this example, the `Access-Control-Allow-Origin` header is set to `*`, allowing any domain to access the resources. This could indicate a CORS misconfiguration vulnerability.



### Deep Dive in signs:

Cross-Origin Resource Sharing (CORS) is a security mechanism that allows resources to be requested from a domain other than the one serving the webpage. Misconfigurations in CORS policies can lead to security vulnerabilities and expose sensitive data. Here are signs of CORS misconfiguration and the parameters you should check to find them:

1\. **Access-Control-Allow-Origin**:

* Sign: The header is set to `*` or allows multiple domains.
* Steps:
  * Make a request to the target application's API endpoint using a tool like Postman or curl.
  * Check if the response header `Access-Control-Allow-Origin` is set to `*`. If it is, the application might be vulnerable to CORS misconfiguration.
  * Example: `Access-Control-Allow-Origin: *`

2\. **Access-Control-Allow-Methods**:

* Sign: Unnecessary or insecure HTTP methods are allowed.
* Steps:
  * Make a request to the target application's API endpoint using a tool like Postman or curl.
  * Check if the `Access-Control-Allow-Methods` header includes insecure methods like `PUT`, `DELETE`, or `CONNECT`. If it does, the application might be vulnerable to CORS misconfiguration.
  * Example: `Access-Control-Allow-Methods: GET, POST, PUT, DELETE`

3\. **Access-Control-Allow-Headers**:

* Sign: Unnecessary or insecure headers are allowed.
* Steps:
  * Make a request to the target application's API endpoint using a tool like Postman or curl.
  * Check if the `Access-Control-Allow-Headers` header allows headers like `X-Frame-Options`, `Content-Security-Policy`, or custom headers. If it does, the application might be vulnerable to CORS misconfiguration.
  * Example: `Access-Control-Allow-Headers: X-Frame-Options, Content-Security-Policy, Custom-Header-1`

4\. **Access-Control-Allow-Credentials**:

* Sign: The header is set to `true`.
* Steps:
  * Make a request to the target application's API endpoint using a tool like Postman or curl.
  * Check if the `Access-Control-Allow-Credentials` header is set to `true`. If it is, the application might be vulnerable to CORS misconfiguration, allowing cross-origin requests with credentials.
  * Example: `Access-Control-Allow-Credentials: true`



The Automation code can be something like this:

{% code overflow="wrap" %}
```sh
cat assets | while read domain; do httpx -H "Origin: https://$domain" -sr -silent; done
```
{% endcode %}

The provided command is a shell script that reads domain names from a file named "assets" and uses the "httpx" tool to test each domain by sending a request with the `Origin` header set to the domain. Here's how the command works:

1. `cat assets`: The `cat` command is used to read the contents of the "assets" file.
2. `| while read domain; do ... done`: The output of the `cat` command is piped to a `while` loop that reads each line (domain name) from the input.
3. `httpx -H "Origin: https://$domain" -sr -silent`: The `httpx` command is used to send an HTTP request to the domain name with the `Origin` header set to the specified domain.
   * `-H "Origin: https://$domain"`: This option sets the `Origin` header to the current domain.
   * `-sr`: This option tells `httpx` to follow redirects.
   * `-silent`: This option suppresses the output of the command, making it suitable for automated testing.

The command will iterate over each domain name in the "assets" file, send an HTTP request with the `Origin` header set to the domain, and print the results. This can be useful for finding CORS misconfiguration vulnerabilities by checking the responses for any unexpected behavior or missing CORS headers.

Example output:

{% code overflow="wrap" %}
```python
https://example.com -> https://www.example.com [Status: 301 Moved Permanently]
https://subdomain.example.com -> https://www.subdomain.example.com [Status: 301 Moved Permanently]
https://anotherdomain.com -> https://www.anotherdomain.com [Status: 301 Moved Permanently]
...
```
{% endcode %}

Each line in the output represents the result of an HTTP request to a domain from the "assets" file. It shows the initial URL, the final redirect URL (if any), and the HTTP status code.

GF filter:

```python
{    "flags": "-HriE",    "patterns": [        "Access-Control-Allow-Origin"    ]}
```

The provided "GF filter" appears to be a configuration for using `gf`, which is a command-line tool for parsing and filtering text using predefined patterns. This filter configuration specifies flags and patterns to search for within text data.

Let's break down the filter configuration:

* **Flags**:
  * `-HriE`: These are flags passed to `gf` modify its behavior.
    * `-H`: Output headers.
    * `-r`: Enable regex mode for pattern matching.
    * `-i`: Case-insensitive matching.
    * `-E`: Use extended regex syntax.
* **Patterns**:
  * `"Access-Control-Allow-Origin"`: This is the pattern that `gf` will search for in the text data. It looks for occurrences of the specified string, which typically indicates the presence of the Access-Control-Allow-Origin header.

Now, let's consider what the output might look like when using this filter configuration with `gf`:

* If the input text contains the specified pattern:
  * `gf` will output lines containing occurrences of the pattern, along with any surrounding context depending on the flags used.
  * Each line may represent a match for the pattern within the input text.
* If the input text does not contain the specified pattern:
  * There will be no output from `gf`.

Example output (hypothetical):

```python
Access-Control-Allow-Origin: *
Access-Control-Allow-Origin: https://example.com
```

In this example, `gf` has found two occurrences of the "Access-Control-Allow-Origin" header in the input text. Each line represents a match found by `gf`, indicating the presence of the header and its value.



Real-world example:

[https://infosecwriteups.com/chaining-cors-by-reflected-xss-to-steal-sensitive-data-c456e133c10d](https://infosecwriteups.com/chaining-cors-by-reflected-xss-to-steal-sensitive-data-c456e133c10d)



### Request and Response samples:

**Access-Control-Allow-Origin: \* (Wildcard):**

Request Header

```
Origin: https://attacker.com
```

Response Header

```
Access-Control-Allow-Origin: *
```



**Access-Control-Allow-Methods: Unnecessary or Insecure HTTP Methods:**

Request Header

```
Origin: https://attacker.com
Access-Control-Request-Method: DELETE
```

Response Header

```
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Methods: GET, POST, PUT, DELETE
```



**Access-Control-Allow-Headers: Unnecessary or Insecure Headers:**

Request Header

```
Origin: https://attacker.com
Access-Control-Request-Headers: X-Frame-Options
```

Response Header

```
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Headers: X-Frame-Options
```



**Access-Control-Allow-Credentials: true**

Request Header

```
Origin: https://attacker.com
```

Response Header

```
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Credentials: true
```

In each of these examples, the server's response headers indicate potential CORS misconfiguration. By allowing wildcard origins, unnecessary or insecure HTTP methods, and headers, or by allowing credentials for cross-origin requests, the server is potentially exposing resources or data to unauthorized access or manipulation.



## <mark style="color:red;">Asset → HTTPX → CORS Misconfiguration</mark>

1. **Asset Discovery**:
   * The first step is to identify the assets or web applications that need to be tested.
   * Tools like `assetfinder` or `subfinder` can be used to discover subdomains and other assets related to the target.
2. **HTTPX**:
   * HTTPX is a fast and feature-rich HTTP client that can be used to check the CORS configuration of the identified assets.
   * The provided automation code sends an HTTP request with the `Origin` header set to the current domain being tested.
   * This helps identify instances where the CORS configuration is too permissive, allowing the application to be accessed from any origin.
3. **CORS Misconfiguration**:
   * CORS is a security mechanism implemented by web browsers to restrict cross-origin requests.
   * A misconfigured CORS policy can allow an attacker to access sensitive data or perform unauthorized actions on behalf of the victim.
   * Common CORS misconfigurations include:
     * Allowing all origins (`Access-Control-Allow-Origin: *`)
     * Allowing overly broad or insecure origin patterns
     * Failing to properly validate the `Origin` header
4. **GF (Gf) Filter**:
   * GF is a tool that can be used to quickly identify patterns in the output of other tools.
   * The provided GF filter looks for the `Access-Control-Allow-Origin` header in the HTTP response, which is a key indicator of CORS misconfiguration.
   * The `-HriE` flags instruct GF to show the headers, response, and error output, making it easier to analyze the CORS configuration.
5. **Necessary Knowledge and Tools**:
   * Understanding of web application security concepts, including the same-origin policy and CORS.
   * Familiarity with command-line tools and scripting, particularly in a Unix-like environment.
   * Knowledge of using tools like `assetfinder`, `subfinder`, `HTTPX`, and `GF`.
   * Understanding of how to interpret and analyze the output of these tools to identify potential CORS misconfigurations.



### CORS (Cross-Origin Resource Sharing) misconfiguration&#x20;

1. **CORS Misconfiguration Overview**:
   * CORS is a security mechanism implemented by web browsers to restrict cross-origin requests.
   * A misconfigured CORS policy can allow an attacker to access sensitive data or perform unauthorized actions on behalf of the victim.
   * Common CORS misconfigurations include:
     * Allowing all origins (`Access-Control-Allow-Origin: *`)
     * Allowing overly broad or insecure origin patterns
     * Failing to properly validate the `Origin` header
2. **CORS Misconfiguration Testing Methodology**:
   * **Asset Discovery**: Identify the web applications and assets that need to be tested. Tools like `assetfinder` or `subfinder` can be used for this.
   * **CORS Probing**: Use a tool like `HTTPX` to send requests with different `Origin` headers and observe the response. Look for the `Access-Control-Allow-Origin` header in the response.
   * **GF (Gf) Filtering**: Use the GF tool to quickly identify patterns in the HTTPX output, specifically looking for the `Access-Control-Allow-Origin` header.
   * **Manual Verification**: Manually inspect the CORS configuration to understand the extent of the misconfiguration and its potential impact.
   * **Exploit Development**: If a vulnerable CORS configuration is identified, attempt to develop an exploit to demonstrate the impact, such as unauthorized access to sensitive data or performing actions on behalf of the victim.
3. **Necessary Knowledge and Tools**:
   * Understanding of web application security concepts, including the same-origin policy and CORS.
   * Familiarity with command-line tools and scripting, particularly in a Unix-like environment.
   * Knowledge of using tools like `assetfinder`, `subfinder`, `HTTPX`, and `GF`.
   * Understanding of how to interpret and analyze the output of these tools to identify potential CORS misconfigurations.
   * Ability to manually inspect and verify CORS configurations, and develop exploits to demonstrate the impact of the vulnerability.
4. **Recommendations**:
   * Set up a test environment to practice and experiment with the CORS misconfiguration testing process.
   * Familiarize yourself with the documentation and best practices for using the mentioned tools.
   * Develop a comprehensive CORS vulnerability testing methodology that includes the steps outlined above.
   * Continuously update your knowledge of the latest web application vulnerabilities, security trends, and tool updates.
   * Collaborate with the security community and participate in bug bounty programs to gain practical experience.
   * Document your findings, report any vulnerabilities responsibly, and follow the appropriate disclosure process.
   * Stay adaptable and be willing to experiment with new tools and techniques as the cybersecurity landscape evolves.

### This can be done using this way:

Use Subfinder or any other tools to find subdomains, then Use the subdomains to test for CORS misconfiguration, You can use the `httpx` tool (as mentioned earlier) to test each subdomain for CORS misconfiguration vulnerabilities.

```
subfinder -d example.com -o subdomains.txt
```

{% code overflow="wrap" %}
```
cat subdomains.txt | while read subdomain; do httpx -H "Origin: https://$subdomain" -sr -silent; done
```
{% endcode %}



## <mark style="background-color:red;">Information Disclosure</mark>

Information Disclosure is a type of security vulnerability that occurs when unauthorized individuals gain access to sensitive information. This information could include usernames, passwords, credit card details, or other confidential data. Hackers often target websites, web applications, and online services to find vulnerabilities that could lead to information disclosure.

Tools and resources:

* Nmap: A network scanning tool used for vulnerability scanning and port scanning.
* Burp Suite: A web application security testing tool used for testing web applications.
* OWASP ZAP: An open-source web application security scanner used for automated testing.
* sqlmap: A tool used for SQL injection testing and exploitation.
* Google Dorking: Advanced search techniques used to find hidden content or files.
* Wayback Machine: A web archive that allows you to see how websites have changed over time.

## <mark style="color:red;">Assets → Backup Fuzzer → Information Disclosure</mark>

1. **Asset Discovery**:
   * The first step is to identify the assets or web applications that need to be tested.
   * Tools like `assetfinder` or `subfinder` can be used to discover subdomains and other assets related to the target.
2. **Backup File Fuzzing**:
   * The process of discovering backup files is often referred to as "backup fuzzing."
   * The goal is to identify any backup files or archives that may be accessible on the target web application.
   * These backup files can potentially contain sensitive information, configuration details, or even source code that could be leveraged for further attacks.
3. **Backup File Wordlist Generation**:
   * Based on the target domain, you can generate a wordlist of potential backup file names and extensions.
   * The example you provided demonstrates a good approach, generating variations like `domain.tld.(rar|tar.gz|7z|gzip|back)`, `www.domain.tld.(rar|tar.gz|7z|gzip|back)`, and `www.domain.(rar|tar.gz|7z|gzip|back)`.
   * This approach covers common backup file extensions and different subdomain/domain combinations.
4. **Backup File Enumeration and Discovery**:
   * Use a script or tool to send HTTP requests to the generated backup file paths and check for their existence.
   * If a backup file is discovered, analyze its contents for any sensitive information, configuration details, or potential vulnerabilities.
5. **Information Disclosure**:
   * Backup files can often contain sensitive information, such as database credentials, API keys, or even source code, which can lead to further vulnerabilities or data breaches.
   * Carefully review the contents of any discovered backup files and assess the potential impact of the information disclosure.

Here's a sample Python script that demonstrates how you might approach finding information disclosure vulnerabilities using tools and codes:

```python
import requests
from bs4 import BeautifulSoup

def check_backup_file(url, backup_files):
  for backup_file in backup_files:
    backup_url = f"{url}/{backup_file}"
    try:
      response = requests.get(backup_url)
      if response.status_code == 200:
        return backup_url
    except requests.exceptions.RequestException as e:
      print(f"Error: {e}")
  return None

def generate_wordlist(domain):
    wordlist = []
    parts = domain.split(".")
    for part in parts:
        wordlist.extend([part, part.capitalize(), part.upper()])
    return wordlist

def main():
  targets = [
    "https://example.com"
  ]
  backup_files = [
    "backup.php",
    "backup.html",
    "backup.txt",
    "backup.bak",
    "backup.old",
    "backup.inc"
  ]

  for target in targets:
    wordlist = generate_wordlist(target)
    for word in wordlist:
      url = f"{target}/{word}"
      backup_url = check_backup_file(url, backup_files)  # Moved inside loop
      if backup_url:
        print(f"Backup file found: {backup_url}")

if __name__ == "__main__":
  main()

```

In this script:

1. The `check_backup_file` function sends HTTP requests to common backup file names and checks if any of them returns a 200 status code.
2. The `generate_wordlist` function creates a wordlist based on the target domain by splitting it into parts and adding variations (lowercase, capitalized, uppercase).
3. The `main` function iterates over the target URLs, generates wordlists for each target, and checks for backup files at each generated URL.

This script provides a basic example of how you might approach finding information disclosure vulnerabilities by leveraging code and tools. However, please note that this is a simplified version and may need additional error handling, filtering, and refinement based on the specific requirements of your bug bounty program.



## <mark style="background-color:red;">XSS Detector</mark>

XSS (Cross-Site Scripting) Detector is a tool or technique used by security researchers and bug bounty hunters to identify and exploit XSS vulnerabilities in web applications. XSS vulnerabilities occur when an application includes user-supplied data in the generated output without proper validation and encoding, allowing attackers to execute malicious scripts in the victim's browser. To perform XSS detection, a bug bounty hunter needs to follow these general steps:

1. Identify input points: Find locations in the target application where user input is accepted, such as search fields, contact forms, or URL parameters.
2. Insert test payloads: Input XSS test payloads into the identified input points to check if they get executed in the browser. Example payloads include **`<script>alert('XSS')</script>`**, **`<svg/onload=alert('XSS')>`**, or **`<img src="x" onerror="alert('XSS')">`**.
3. Observe output: Monitor the application's response for signs of script execution, such as pop-up dialogs, console logs, or DOM changes.
4. Report vulnerability: If the application is vulnerable to XSS, provide a detailed report to the application's owner, explaining the issue, its impact, and how to reproduce it.

There are several tools and methods for XSS detection, including:

**Manual testing**: Using a web browser and intercepting proxy tools like Burp Suite or ZAP, you can manually test for XSS vulnerabilities by manipulating requests and observing the application's behavior.

**Browser extensions**: Extensions like XSS Analyzer or XSS Finder can help identify potential XSS vulnerabilities by scanning web pages and highlighting potential injection points.

**Automated scanners**: Tools like Acunetix, Nessus, or Nikto can perform automated scans of web applications, checking for various vulnerabilities, including XSS.

**XSS Polyglots**: These are XSS payloads that work in multiple contexts, such as within script tags, event handlers, or HTML attributes. Using a variety of XSS polyglots can help increase your chances of identifying vulnerabilities.



Here's a refined version of the flow with additional details:

1. **Input**: Provide the target website URL as input to FLinks. FLinks is a tool that extracts links from web pages.
2. **URL Extraction and Validation**: FLinks extracts URLs from the provided website and ensures they return a 200 status code, indicating that the pages exist and are accessible.
3. **URL Parameter Extraction**: For each validated URL, extract the list of parameters present in the URL query string. These parameters can potentially be vulnerable to XSS attacks.
4. **Parameter Fuzzing**: Run a fuzzing tool, like Wfuzz or Ffuf, on each URL with the extracted parameters to discover hidden or non-obvious parameters that might be vulnerable to XSS.
5. **XSS Detection**: Utilize an automated XSS detection tool, such as XSStrike, XSSer, or SQLmap, to identify potential XSS vulnerabilities in the discovered parameters.
6. **Manual Verification and Exploitation**: Review the results from the automated tool and manually verify the identified vulnerabilities. Craft custom XSS payloads to exploit the vulnerabilities and demonstrate their impact. This may involve bypassing WAF (Web Application Firewall) filters or evading client-side security mechanisms.
7. **Reporting**: Compile a detailed report with the verified XSS vulnerabilities, including steps to reproduce the issue, affected URL(s), and potential impact. Submit the report to the bug bounty program or website owner for further action.

### Light Flow:

Here is an enhanced flow for a hunter to detect XSS:

1. Begin by identifying the target website and its input fields (FLinks).
2. Utilize a tool to send HTTP requests to the website, capturing the responses. Ensure that the tool follows redirects and validates the status code (200) for alive URLs.
3. Parse the responses to extract URLs and their parameter lists.
4. Use a parameter fuzzing tool to discover hidden parameters and variations in the URLs.
5. Employ a security scanning tool, such as a web application scanner or a specialized XSS scanner, to detect potential XSS vulnerabilities. This tool should support both reflected and stored XSS detection.
6. Manually verify the detected XSS vulnerabilities using a debugging proxy or a browser's developer tools. Modify the requests and analyze the responses to confirm the presence of XSS.
7. Document the findings, including the vulnerable URL, parameter, payload, and any necessary conditions for exploitation.

Additional Steps:

1. Consider using automated tools like Burp Suite, OWASP ZAP, or other web application scanners to streamline the process.
2. Utilize a fuzzing tool like `sqlmap` or `parameth` to discover hidden parameters and injection points.
3. Leverage security testing frameworks like `NoSQLMap`, `Damn Small Thor` (DST), or `commix` to automate the detection and exploitation of XSS vulnerabilities.
4. Perform manual testing and code review to validate and complement the automated tools' results.
5. Keep up-to-date with the latest XSS techniques, payloads, and bypass methods to enhance your detection capabilities.
6. Regularly update your tools and techniques to account for new web technologies, frameworks, and security measures.

### Heavy Flow:

1. Website as input goes to FLinks, which is a tool that crawls websites and extracts URLs.
2. FLinks makes some URLs, and checks if they are alive and have a `200` status code.
3. Open **all URLs** to extract parameter lists, and **merge the lists**. Tools like Burp or OWASP ZAP can be used for this.
4. Run a parameter fuzzing tool like Arjun or XSStrike on **all URLs** to discover hidden parameters. The fuzzing tool will test for common XSS payloads and look for parameters that respond differently.
5. Run a tool like XSSHunter or XSSYA to detect XSS vulnerabilities. This tool will scan the website for XSS vulnerabilities based on a set of predefined rules.
6. Work on the results manually to discover or verify the XSS. Look at the source code, try common XSS payloads, and use tools like Burp or OWASP ZAP to intercept and modify requests.

Here is a Python script that demonstrates the flow using the `requests` library for making HTTP requests and the `re` module for regular expressions:

```python
import requests
import re

# Step 1: Get website input
website = input("Enter the website URL: ")

# Step 2: Use FLinks to get URLs and check their status
urls = []
# Run FLinks and store the URLs in the `urls` list
# ...

# Check if URLs are alive and have 200 status code
alive_urls = []
for url in urls:
    try:
        response = requests.get(url)
        if response.status_code == 200:
            alive_urls.append(url)
    except:
        pass

# Step 3: Extract parameter lists and merge
parameter_lists = []
for url in alive_urls:
    response = requests.get(url)
    params = re.findall(r'<input.*name="(.+?)".*>', response.text)
    parameter_lists.extend(params)

parameter_lists = list(set(parameter_lists))  # Remove duplicates

# Step 4: Run parameter fuzzing tool
fuzzed_urls = []
for param in parameter_lists:
    for url in alive_urls:
        if f'{param}=' in url:
            fuzzed_urls.append(f'{url}{param}=<script>alert("XSS")</script>')

# Step 5: Run XSS detection tool
xss_urls = []
for url in fuzzed_urls:
    response = requests.get(url)
    if '<script>alert("XSS")</script>' in response.text:
        xss_urls.append(url)

# Step 6: Work on results manually
for url in xss_urls:
    print(f"Potential XSS found: {url}")
    # Check the source code and manually test for XSS

print("XSS detection completed.")
```

This script provides a high-level overview of the flow. In practice, you would need to replace the `# ...` comments with actual code that runs FLinks, integrates with Burp or OWASP ZAP for parameter extraction and fuzzing, and uses XSS detection tools like `XSSHunter` or `XSSYA`.



### Useful tools :

1. **Wfuzz**: A Python-based tool that helps bug bounty hunters brute-force web applications, useful for identifying resources and parameters vulnerable to XSS.
2. **Nuclei**: A fast and customizable vulnerability scanner that can detect XSS and other common vulnerabilities.
3. **Nmap**: A network scanning tool that can be used for reconnaissance and identifying potential XSS targets.
4. **FFUF**: A fast web fuzzer that can be used to discover hidden parameters and directories, as well as test for XSS vulnerabilities.
5. 4-**ZERO-3 bypass**: A tool that can help bypass WAFs and discover XSS vulnerabilities.
6. **Whatweb**: A tool for identifying web technologies, CMS, and other information that can be useful in finding XSS vulnerabilities.
7. **Waybackurl**: A tool that retrieves URLs from the Wayback Machine, which can be used to discover old, potentially vulnerable versions of web pages.
8. **Waf00f**: A tool for identifying and fingerprinting WAFs, which can be helpful when trying to bypass them to discover XSS vulnerabilities.
9. **Burp Suite**: A comprehensive web application testing toolkit that includes features for finding XSS vulnerabilities, intercepting and modifying requests, and more.
10. **Dalfox** -&#x20;
11. **ezXSS** -





## <mark style="color:red;">Assets → FLinks → HTTPx → XSS Detector</mark>

### Light Flow

**Breakdown of the Flow:**

1. **Assets → FLinks:**
   * **What it does:** This step likely refers to gathering potential website URLs. "Assets" could be a list of URLs, a website domain, or a file containing URLs.
   * **Tools:**
     * You might use a tool like **Subfinder** to discover subdomains of a target website, expanding the attack surface.
     * If you have a specific website domain, you can directly use it.
   * **Knowledge:** Understanding of subdomain enumeration techniques.
2. **FLinks → HTTPx:**
   * **What it does:** FLinks likely refers to a custom script or tool that processes the URLs from the previous step. It might perform tasks like:
     * Validating URLs for proper format.
     * Checking if URLs are alive using tools like **HTTPX** or libraries within the script.
     * Removing duplicates to avoid redundant testing.
   * **Tools:**
     * Consider using a tool like \*\* portero\*\* to automate URL validation and filtering.
   * **Knowledge:**
     * Basic understanding of URL structures and validation.
3. **Open each URL to extract parameter lists:**
   * **What it does:** This step involves retrieving the HTML content of each valid URL and parsing it to identify potential parameters within forms, query strings, etc.
   * **Tools:**
     * Libraries like **BeautifulSoup** or **lxml** can be used for parsing HTML content in Python.
     * Consider browser developer tools for manual extraction in specific scenarios.
   * **Knowledge:**
     * HTML structure and ability to identify parameters in web forms and URLs.
4. **Run a parameter fuzzing tool:**
   * **What it does:** Fuzzing involves sending various inputs to a parameter to identify vulnerabilities. In this case, the tool would likely inject different payloads into the identified parameters and submit the requests.
   * **Tools:**
     * Popular fuzzing tools like **Burp Suite** (Intruder module) or **FFUF** can be used for this purpose.
   * **Knowledge:**
     * Understanding of parameter fuzzing techniques and crafting effective XSS payloads.
5. **Run a tool to detect XSS or reflections:**
   * **What it does:** This step involves using a tool that analyzes the responses from the fuzzed requests to identify potential XSS vulnerabilities. The tool might look for specific patterns or behaviors that indicate reflected scripts.
   * **Tools:**
     * Tools like **XSS Scan** or custom scripts can be used to automate XSS detection. Burp Suite also offers functionalities for detecting reflected scripts.
   * **Knowledge:**
     * Familiarity with common XSS signatures and how tools detect them.
6. **Work on the results manually to discover or verify the XSS:**
   * **What it does:** Automated tools might generate false positives. This step involves manually reviewing the identified potential vulnerabilities to confirm if they are indeed XSS and assess their severity.
   * **Tools:**
     * Browser developer tools are crucial for manual testing and exploiting potential XSS to verify their impact.
   * **Knowledge:**
     * Hands-on experience with XSS testing and understanding different XSS types (reflected, stored, DOM-based).

**In a nutshell:**

1. Website as an input goes to FLinks
2. Flinks makes some URLs, make sure the URLs are alive and have `200` status code
3. Open each URL to extract parameter lists
4. Run a parameter fuzzing tool on the URL to discover hidden parameters
5. Run a tool to detect XSS or reflections
6. Work on the results manually to discover or verify the XSS

<figure><img src=".gitbook/assets/Untitled Diagram.jpg" alt=""><figcaption></figcaption></figure>



### Heavy Flow

**Breakdown of the Flow:**

1. **Asset Discovery**:
   * Identify the web applications and assets to be tested using tools like `assetfinder` or `subfinder`.
2. **FLinks**:
   * Use FLinks to extract the hyperlinks from the discovered assets.
3. **HTTPX**:
   * Use HTTPX to check the status of the links extracted by FLinks, focusing on the 200 status code responses.
4. **Parameter Extraction**:
   * Open **all** the URLs, not just the ones with a 200 status code, to extract the parameter lists.
   * Merge the parameter lists from all the URLs to create a comprehensive list.
5. **Parameter Fuzzing**:
   * Use a parameter fuzzing tool, such as Burp Suite's Intruder or a custom script, to discover any hidden parameters that may not be readily visible in the URL.
   * Fuzz all the URLs, not just the ones with a 200 status code, to ensure a thorough test.
6. **XSS Vulnerability Scanning**:
   * Employ specialized XSS detection tools, such as Burp Suite's Reflected XSS Scanner or OWASP ZAP's XSS Scanner, to identify potential Cross-Site Scripting vulnerabilities.
7. **Manual Verification**:
   * Carefully review the results from the automated XSS scanning tools and manually verify the existence and impact of the identified vulnerabilities.
   * Craft custom payloads, analyze the application's behavior, and ensure the vulnerability can be reliably reproduced.

**Necessary Knowledge and Tools**:

* Understanding of web application security concepts, including Cross-Site Scripting (XSS) vulnerabilities.
* Familiarity with command-line tools and scripting, particularly in a Unix-like environment.
* Knowledge of using tools like `assetfinder`, `subfinder`, `FLinks`, `HTTPX`, Burp Suite, and OWASP ZAP.
* Proficiency in manual web application testing techniques, such as parameter extraction, parameter fuzzing, and XSS payload development.
* Ability to analyze the output of the tools and effectively identify and verify XSS vulnerabilities.

**In a nutshell:**

1. Website as an input goes to FLinks,
2. Flinks makes some URLs, make sure the URLs are alive and have `200` status code
3. Open **all URLs** to extract parameter lists, **merge the lists**
4. Run a parameter fuzzing tool **on all URLs** to discover hidden parameters
5. Run a tool to detect XSS or reflections
6. Work on the results manually to discover or verify the XSS

<figure><img src=".gitbook/assets/Untitled Diagram(1).jpg" alt=""><figcaption></figcaption></figure>



Here are ten popular parameter fuzzing tools for bug bounty hunters:

1. **HackBar**: A Mozilla Firefox add-on that allows for security auditing and penetration testing, including testing for XSS holes and SQL injections.
2. **Wfuzz**: A Python-based tool that helps to sniff out resources not linked, such as directories and scripts, and perform POST and GET parameter-checking for multiple types of injections.
3. **IronWASP**: A web security scanner that is open source and free to use, providing features like login sequence recording, false-positive and negative-positive detection, and easy-to-use GUI.
4. **INalyzer**: A tool for manipulating iOS applications, focusing on methods and parameters, and targeting closed applications.
5. **Burp Suite**: A comprehensive web vulnerability scanner and proxy tool that supports various types of attachment insertion points and nested insertion points.
6. **PeachPy**: A fuzzing tool from the Peach project, focusing on protocol and file format fuzzing, allowing for the crafting of specific test cases for various applications.
7. **WinAFL**: A fork of AFL designed specifically for fuzzing Windows applications, supporting various coverage-guided fuzzing techniques.
8. **Fuzzilli**: A JavaScript engine fuzzer that targets web browsers, generating highly complex and mutated JavaScript code to test the browser's scripting engine for vulnerabilities.
9. **zzuf**: A lightweight fuzzer that tests command-line utilities, including files and standard input, to uncover crashes and potential vulnerabilities.
10. **OWASP ZAP**: A popular free web security tool that is actively maintained by a dedicated international team, offering features like automated scanning, manual testing, and reporting.



Here are ten popular XSS or reflection tools for bug bounty:

1. **XSS Validator**: A Burp Suite extender designed for automation and validation of XSS vulnerabilities.
2. **XSScrapy**: An XSS spider that crawls web pages and checks for XSS vulnerabilities.
3. **XSStrike**: The most advanced XSS scanner.
4. **xssor2**: An XSS'OR tool that allows users to test XSS vulnerabilities.
5. **xsshunter**: A portable version of XSSHunter.com that helps identify XSS vulnerabilities.
6. **dalfox**: A parameter analysis and XSS scanning tool based on Golang.
7. **xsser**: A tool that detects, exploits, and reports XSS vulnerabilities in web-based applications.
8. **XSpear**: A powerful XSS scanning and parameter analysis tool.
9. **weaponised-XSS-payloads**: XSS payloads designed to turn alert(1) into P1.
10. **XSS-Radar**: A tool that detects parameters and fuzzes them for cross-site scripting vulnerabilities.



## <mark style="color:red;">Fuzzing on various properties</mark>

1. **Parameter Discovery**:
   * As mentioned by zseanos, the key to successful vulnerability discovery is parameter discovery.
   * Fuzzing can be used to test for hidden parameters that are not explicitly mentioned in the application's documentation or code. By sending different parameter values, you can discover parameters that are not used in the application's code but still affect the application's behavior.
   * The "InputScanner" tool, or similar approaches, can be used to easily scrape each endpoint for any input names or IDs listed on the page.
   * These discovered parameters can then be tested using tools like Burp Suite Intruder for common vulnerabilities, such as Cross-Site Scripting (XSS).
2. **Hidden Endpoint Discovery**:
   * In addition to parameter discovery, finding hidden or undocumented endpoints can also lead to the discovery of vulnerabilities.
   * Fuzzing can be used to discover hidden endpoints that are not linked to the application's main pages. By fuzzing URLs and looking for 404 responses or redirects, you can find endpoints that are not accessible directly but can still be accessed through other means.
   * Tools like FFUF, GoBuster, KiteRunner, and IIS-Shortname-Scanner can be used to perform directory and file fuzzing to uncover these hidden endpoints.
3. **Hidden File Discovery**:
   * Similar to hidden endpoint discovery, finding hidden or sensitive files can also be valuable in the vulnerability discovery process.
   * Fuzzing can help in discovering hidden files that are not linked to the application's main pages. By fuzzing URLs with common file extensions (e.g., .php, .html, .txt), you can find files that are not accessible directly but can still be accessed through other means.
   * The same fuzzing tools mentioned above can be used to search for various file extensions, such as `.tar.gz`, `.zip`, `.7z`, `.phps`, `.php~`, and `.sh`, to uncover potentially sensitive files.



### Fuzzing files and directories

1. **Verify Method**:
   * Before starting the fuzzing process, it's important to ensure that you can find an existing file on the target site.
   * Choose a web application or website you want to test for hidden files and directories. This could be a specific application or a subdomain of a larger website. Always make sure you have permission or follow the guidelines provided by a bug bounty program.
   * This "Verify Method" helps you confirm that the fuzzing process is working as expected and that you can successfully retrieve a file from the server.
   * For example, if there is a file at `/file.ext` that returns a 200 status code, you can proceed with the fuzzing process.
2. **Fuzzing Process**:
   * Once you have verified that you can successfully retrieve a file, you can start the fuzzing process.
   * Popular fuzzing tools include FFUF, Wfuzz, and Burp Suite's Intruder. Choose the tool that best suits your needs and is compatible with the target website.
   * Each tool has its configuration options. Generally, you'll need to specify the target website's base URL (e.g., https://example.com/) and provide the wordlist you created word list. Additional configuration options may include setting the number of concurrent connections, request timeout, and user-agent strings.
   * The command `ffuf -w list -u "https://site.com/FUZZ" -ac` can be used, where `list` is the wordlist containing the file or directory you want to fuzz.
   * Launch the fuzzing process, which will start sending HTTP requests to the target website, appending each word from the wordlist to the base URL. The tool will then record the HTTP response codes for each request.
   * During the fuzzing process, you should monitor the tool's output for interesting HTTP response codes:
     * 200 OK: This indicates a successful request, meaning a file or directory was found. Investigate these results for potential vulnerabilities.
     * 301 Moved Permanently or 302 Found: These indicate that the requested resource has been moved to a different location. Follow the redirects and investigate the new URLs.
     * 401 Unauthorized or 403 Forbidden: These responses suggest that the resource might exist but requires authentication or is intentionally hidden.
     * 404 Not Found: This is the standard response for non-existent resources, so it is less interesting in this context.
3. **Wordlist Considerations**:
   * It's recommended to create your customized wordlist based on the context of the target website.
   * A wordlist is a collection of potential file and directory names that you'll use during the fuzzing process. Some common entries include "admin," "backup," "secret," "config," and "robots.txt." You can create a wordlist yourself, download pre-made lists from the internet, or use built-in lists provided by fuzzing tools.
   * Avoid using generic wordlists, as they may not be as effective in discovering vulnerabilities.
4. **Context-Aware Fuzzing**:
   * Adjust your fuzzing approach based on the type of web application or API you're testing.
   * For example, skip file fuzzing on web applications running on Express, as they typically don't serve files directly.
   * For REST APIs, focus on fuzzing the last part of the endpoint, as the other parts are likely to be well-defined.
   * Once you've identified potential hidden files or directories, manually inspect them for vulnerabilities. Look for sensitive information disclosures, configuration files, exposed login portals, or other exploitable weaknesses.
5. **Evasion Techniques**:
   * Change the `User-Agent` header to avoid getting blocked by the target website or CDN.
   * Tune the number of threads to avoid overwhelming the target and triggering bans or rate-limiting.
   * Be mindful of the target's CDN configuration and adjust your fuzzing approach accordingly.



### Fuzzing Endpoints

Fuzzing endpoints involves several steps, and the signs of finding hidden endpoints can vary depending on the target application's security posture and configuration. Here's a more detailed explanation of each step and the signs you should look for:

1. **Identify Endpoint Patterns**:
   * Look for patterns in the application's URL structure, such as the use of underscores, dashes, or camel case.
   * Examine the application's documentation or source code to identify any endpoints that are not explicitly mentioned.
   * Use tools like Burp Suite or OWASP ZAP to analyze the application's structure and identify potential hidden endpoints.
2. **Create Endpoint List**:
   * Generate a list of endpoint names based on the identified patterns, including variations such as lowercase, uppercase, and mixed case.
   * Use tools like DirBuster or wfuzz to create a comprehensive list of endpoints.
3. **Test Endpoints**:
   * Send requests to the target application's URLs with the endpoint names from the list.
   * Look for any changes in the response codes, such as 404 (Not Found) or 302 (Redirect).
   * Analyze the response headers and examine the application's behavior.
4. **Analyze Responses**:
   * Look for any differences in the response, such as redirects to unexpected pages or error messages.
   * Check the response body for any clues that indicate the presence of hidden endpoints.
   * Use tools like Burp Suite or OWASP ZAP to intercept and analyze the requests and responses.
5. **Validate Findings**:
   * Manually test the discovered endpoints to confirm their existence and assess their security implications.
   * Check for any sensitive or privileged information that could be accessed through the hidden endpoints.
   * Use tools like Burp Suite or OWASP ZAP to analyze the application's security posture and identify any potential vulnerabilities.

During the bug-hunting process, you should be looking for signs of hidden endpoints, such as:

* Unexpected 404 (Not Found) responses when requesting a non-existent endpoint.
* Redirects to unexpected pages when requesting a hidden endpoint.
* Changes in the response body or behavior when requesting a hidden endpoint.
* Sensitive or privileged information is being exposed through hidden endpoints.

Here's a Python script using the `requests` library to demonstrate endpoint fuzzing:

```python
import requests

target_url = "https://example.com"
endpoint_list = ["api", "login", "dashboard", "admin", "config", "secret"]

for endpoint in endpoint_list:
    url = f"{target_url}/{endpoint}"
    response = requests.get(url)
    if response.status_code == 200:
        print(f"Found endpoint: {url}")
```



1. **Fuzzing Endpoints with FFUF**:
   * FFUF (Fuzz Faster U Fool) can be used to fuzz the last part of an endpoint.
   * This is useful when you have a well-defined endpoint structure and want to focus on discovering hidden or undocumented endpoints.
   * The command would look something like: `ffuf -w list.txt -u "https://api.site.com/FUZZ"`, where `list.txt` is your wordlist.
2. **Fuzzing Endpoints with KiteRunner**:
   * KiteRunner is a more comprehensive tool for fuzzing entire endpoints.
   * It allows you to fuzz the entire endpoint structure, not just the last part.
   * This can be useful when the endpoint structure is not as well-defined or when you want to discover more complex endpoint patterns.
3. **Generating Wordlists with KiteRunner**:
   * KiteRunner includes a "KiteBuilder" feature that can help you generate wordlists for endpoint fuzzing.
   * To convert a JSON list to a KiteRunner-compatible wordlist, use the command: `kr kb convert list.json list.kite`.
   * This will create a `list.kite` file that can be used with the KiteRunner scanner.
4. **Fuzzing Endpoints with KiteRunner**:
   * To use KiteRunner for endpoint fuzzing, run the command: `kr scan https://api.site.com -w routes-small.kite --kitebuilder-full-scan`.
   * This will use the `routes-small.kite` wordlist and perform a full scan of the endpoints.



### Fuzzing Parameters

Fuzzing parameters is a technique used by bug bounty hunters to discover hidden parameters and potential vulnerabilities in web applications. Here's a detailed process to follow for parameter fuzzing, along with explanations of signs to look for and tools that can help:

1. **Identify the target**: Choose a web application or website you want to test for hidden parameters. Ensure you have permission or follow the guidelines provided by a bug bounty program.
2. **Identify parameters**: Manually navigate the website and take note of any parameters you encounter in the URL, such as ?id=123 or \&sort=desc. Parameters are often used to pass data to the server and can be a potential source of vulnerabilities.
3. **Create a wordlist**: Build a list of potential parameter names and values to test. Include common parameter names like "id," "user," "page," or "limit." For values, you can use payloads designed to test for common vulnerabilities, such as SQL injection, XSS, or command injection.
4. **Choose a fuzzing tool**: Select a suitable fuzzing tool, such as FFUF, Wfuzz, or Burp Suite's Intruder. These tools can help automate the process of parameter fuzzing and provide customizable options.
5. **Configure the fuzzing tool**: Set up the chosen fuzzing tool with the target website's base URL and the wordlist you created in step 3. You may need to configure the tool to use specific payloads, HTTP methods, headers, or parameters for different requests.
6. **Start fuzzing**: Launch the fuzzing process, which will start sending HTTP requests to the target website, iterating through each parameter and value from the wordlist. The tool will then record the HTTP response codes for each request.
7. **Analyze results**: During the fuzzing process, monitor the tool's output for interesting HTTP response codes and server behaviors:
   * 200 OK: This indicates a successful request, meaning a potential hidden parameter was found. Investigate these results for potential vulnerabilities.
   * 400 Bad Request or 404 Not Found: These responses can help identify invalid parameters or values.
   * 500 Internal Server Error: This may indicate a server-side error, which could be a sign of a vulnerability, such as SQL injection or command injection.
   * 302 Found or 301 Moved Permanently: These responses suggest that the requested resource has been moved to a different location. Follow the redirects and investigate the new URLs.
8. **Parameter Fuzzing Approach**:
   * The goal of parameter fuzzing is to discover hidden or undocumented parameters that may be present in the web application.
   *   One approach is to add a bunch of parameters to the request, as shown in the example:

       ```
       GET /param1=value1&param2=value2&param3=value3&...
       ```
   * This technique can help uncover parameters that may not be obvious from the application's documentation or user interface.
9. **Parameter Fuzzing Tools**:
   * Two popular tools for hidden parameter discovery are Arjun and x8.
   * **Arjun**: This tool uses a smart algorithm to discover hidden parameters by analyzing the application's responses.
   * **x8**: This tool is more advanced and stable than Arjun, and it's recommended for use in this context.
10. **Using x8 for Parameter Fuzzing**:
    * To use x8 for parameter fuzzing, you can follow these steps:
      1. Install the tool: `pip install x8`
      2.  Run the tool on the target URL:

          ```
          x8 -u https://example.com/endpoint
          ```
    * The tool will automatically discover and test various parameters, highlighting any that may be of interest.

Parameter fuzzing is a type of testing in which invalid, unexpected, or random data is input to a program to test its robustness and identify any security vulnerabilities. Here are some tools and manual techniques that can help a bug hunter in parameter fuzzing:

1. **Fuzzing Tools:** There are many open-source and commercial fuzzing tools available that can help automate the process of fuzzing. Some popular fuzzing tools include AFL, American Fuzzy Lop, Peach Fuzzer, and Radamsa. These tools can generate a large number of inputs quickly and efficiently, which can help uncover bugs and vulnerabilities.
2. **Proxy Tools:** Proxy tools like Burp Suite and OWASP ZAP can be used to intercept and modify HTTP requests and responses. These tools can help a bug hunter modify parameters and test the application's behavior under different conditions.
3. **Manual Testing:** Manual testing can be used to identify parameters that are vulnerable to fuzzing. By examining the application's source code or using a tool like Burp Suite, a bug hunter can identify parameters that are processed by the application. These parameters can then be fuzzed manually using tools like curl or Python scripts.
4. **Input Mutation:** Input mutation involves modifying the input data in a systematic way to test the application's behavior. For example, a bug hunter might modify a parameter by changing its length, data type, or format. This can help uncover bugs and vulnerabilities that might not be found using other fuzzing techniques.
5. **Code Analysis:** Code analysis can be used to identify parameters that are processed by the application. By examining the application's source code, a bug hunter can identify parameters that are processed by the application and determine how they are used. This can help a bug hunter focus their fuzzing efforts on the most vulnerable parameters.
6. **Fuzzing Strategies:** There are many fuzzing strategies that can be used to test parameters. Some common strategies include:
   1. **Random Fuzzing:** This involves generating random input data to test the application's behavior.
   2. **Smart Fuzzing:** This involves generating input data based on the application's behavior. For example, a bug hunter might use a tool like AFL to generate input data based on the application's coverage.
   3. **Model-Based Fuzzing:** This involves generating input data based on a model of the application's behavior. For example, a bug hunter might use a tool like Peach Fuzzer to generate input data based on an XML model.

By using these tools and techniques, a bug hunter can effectively fuzz parameters and uncover bugs and vulnerabilities in applications. Many fuzzing strategies can



Sample Python script

```python
import requests
import string

# Set the base URL for the application
base_url = "http://example.com/search"

# Set the parameter to fuzz
param = "q"

# Set the character set to use for fuzzing
charset = string.ascii_letters + string.digits + string.punctuation

# Set the minimum and maximum lengths for the parameter
min_length = 1
max_length = 100

# Loop through the length range
for length in range(min_length, max_length + 1):
    # Generate a random string of the current length
    payload = ''.join(random.choice(charset) for _ in range(length))
    
    # Build the URL with the fuzzed parameter
    url = f"{base_url}?{param}={payload}"
    
    # Send a GET request to the URL
    response = requests.get(url)
    
    # Check the status code of the response
    if response.status_code != 200:
        print(f"[!] Unexpected status code: {response.status_code}")
        print(f"[!] Payload: {payload}")
        print(f"[!] URL: {url}")
        break
```

This script generates a random string of characters for the `q` parameter and sends a GET request to the application. If the application returns a status code other than 200, the script prints an error message and the payload and URL used.



### Where to Fuzz

In the context of bug bounty hunting, fuzzing is a technique used to test software for vulnerabilities by inputting invalid or unexpected data. In the case of React and VueJS applications, there are several areas where fuzzing can be particularly effective.

#### Endpoints Returning Information

Fuzz the endpoints that return information, such as GET requests. This can help identify any potential issues with data validation or sanitization, which could lead to XSS or other vulnerabilities.

#### Files Without Parameters

Fuzz files that do not have any parameters, such as static files like HTML, CSS, or JavaScript. This can help identify any issues with file permissions or access control, which could lead to unauthorized access or data exposure.

#### All Endpoints and Files

Fuzz all endpoints and files to discover extra parameters. This can help identify any hidden functionality or potential vulnerabilities that may not be immediately apparent.

#### Root or Other Directories

Fuzz root or other directories (file and directory fuzz) to uncover any potential issues with file permissions or access control. This can help identify any vulnerabilities related to file manipulation or unauthorized access.

To perform these fuzzing tests, you may need to use specialized tools such as HackBar, Wfuzz, IronWASP, INalyzer, Burp Suite, PeachPy, WinAFL, Fuzzilli, zzuf, or OWASP ZAP. These tools can help automate the process of fuzzing and make it easier to identify vulnerabilities in your React and VueJS applications.



#### During hunting, a bug hunter should focus on fuzzing the following areas:

Application Entry Points:

* Sample: `https://example.com/login`
* Description: The login page is often the main entry point for users to access an application. Fuzzing this endpoint can reveal vulnerabilities such as SQL injection, XSS, or insecure authentication mechanisms.

API Endpoints:

* Sample: `https://api.example.com/v1/users/123`
* Description: API endpoints are used to access the application's functionality programmatically. Fuzzing these endpoints can uncover hidden or unsecured endpoints, as well as vulnerabilities such as authorization bypass, rate-limiting issues, or data exposure.

File Uploads:

* Sample: `https://example.com/upload`
* Description: File upload functionality can introduce vulnerabilities like arbitrary file upload, path traversal, or server-side script execution. Fuzzing file uploads helps identify these security issues.

User Inputs:

* Sample: `https://example.com/search?q=test`
* Description: User inputs are a common target for attackers, as they can be used to inject malicious code or execute unintended actions. Fuzzing user inputs helps uncover XSS, SQL injection, command injection, or other vulnerabilities that can be exploited through user input.

Important signs and links during fuzzing include:

1. `Unexpected 404 (Not Found) responses`: These can indicate hidden or non-existent pages or endpoints. For example, if you receive a 404 error for `https://example.com/admin`, it could mean the admin page is hidden or doesn't exist.
2. `Redirects to unexpected pages`: These can reveal hidden or unlinked pages. If you're redirected to a page like `https://example.com/secret`, it might indicate a hidden page.
3. `Changes in response body or behavior`: These can uncover hidden or insecure functionality. For example, a request to `https://example.com/profile?edit=true` might reveal an edit mode for user profiles that shouldn't be accessible.
4. `Sensitive or privileged information being exposed`: This could indicate unauthorized access to sensitive data. If a request to `https://example.com/users?debug=true` returns user details with password hashes, it's a sign of data exposure.
5. `Error messages or stack traces`: These can provide valuable information about the application's behavior and structure. For example, an error message containing a database connection string might reveal sensitive details about the application's infrastructure.



### Methodology

1. **Crawling and Asset Discovery**:
   * Use tools like FLinks to crawl the target website and save all the file names and paths.
   * Complement this with manual crawling to ensure you have a complete understanding of the application's structure.
2. **Technology Detection**:
   * Identify the web application technologies, frameworks, and libraries used by the target.
   * This information can help you tailor your fuzzing approach and focus on the appropriate vulnerabilities.
3. **Endpoint Fuzzing**:
   * Conduct fuzzing on the full and relative endpoints to discover hidden or undocumented endpoints.
   * Tools like FFUF, GoBuster, or KiteRunner can be used for this purpose.
4. **File and Directory Fuzzing**:
   * Fuzz the file names and directories to discover hidden files and directories.
   * Again, tools like FFUF can be used for this step, following the "Verify Method" as mentioned earlier.
5. **Backup File Discovery**:
   * Use a tool like backupKiller to generate a fuzz list based on the target's site map and fuzz for potential backup files.
6. **Parameter Enumeration**:
   * Use a tool like FallParams to crawl the target and save all the discovered parameters.
7. **Parameter Fuzzing**:
   * Conduct parameter fuzzing to discover hidden or undocumented parameters.
   * Tools like Arjun, x8, or custom scripts can be used for this step.

**Necessary Knowledge and Tools**:

* Understanding of web application security concepts, including common vulnerabilities and attack vectors.
* Familiarity with command-line tools and scripting, particularly in a Unix-like environment.
* Knowledge of using tools like FLinks, FFUF, GoBuster, KiteRunner, backupKiller, FallParams, Arjun, and x8.
* Ability to analyze the output of the various fuzzing tools and identify potentially interesting or vulnerable areas.
* Understanding of web application architecture, file structures, and parameter usage.



### **Examples**

Example 1: a rest API endpoint

```sql
/api/user/699201852
```

Fuzz:

```sql
/api/user/699201852/**FUZZ** // words
/api/user/**FUZZ**/699201852 // words
/api/**FUZZ**/699201852 // words
/api/user**?FUZZ** // params
/api/user/699201852?**FUZZ** // params
```

Example 2: Single PHP page

```sql
/change_password.php
```

Fuzz

{% code overflow="wrap" %}
```sql
/**FUZZ**.php // file names, words
/change_password.php**FUZZ** // "~", ".1", ".2", ".3", ".4", ".5", "s", ".old", ".bk", ".bak"
/**FUZZ**.php**FUZZ**
/change_password.php**?FUZZ**
```
{% endcode %}

Example 3: an Apache root directory (you can code something like **backupKiller**)

[backupKiller](https://www.notion.so/256c5355749042a18848978a8cb32513?pvs=21)

{% code overflow="wrap" %}
```sql
/**FUZZ**.**FUZZ**

// "7z", "back", "backup", "bak", "bck", "bz2", "copy", "gz", "old", "orig", "rar", "sav", "save", "tar", "tar.bz2", "tar.bzip2", "tar.gz", "tar.gzip", "tgz", "tmp", "zip"
```
{% endcode %}



