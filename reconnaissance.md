# Reconnaissance

* Technologies and CMS
* Assets



## <mark style="color:red;">Technologies and CMS - Assets</mark>

**What it is:**

* This section focuses on identifying the technologies and Content Management Systems (CMS) used by the target website or application.

**Why it's important:**

* Knowing the technologies and CMS helps tailor your approach to finding vulnerabilities.
* Different technologies and CMS have known weaknesses or common misconfigurations you can exploit.
* Many tools and techniques are specific to particular technologies or CMS.

**What to do:**

1. **Gather information:**
   * Use browser developer tools to inspect source code, libraries, and scripts.
   * Look for meta tags, comments, or copyright notices that might reveal technologies.
   * Utilize tools like Wappalyzer or BuiltWith to fingerprint technologies.
2. **Research vulnerabilities:**
   * Once you identify a technology or CMS, research known vulnerabilities specific to it.
   * Exploit databases like CVE Details or vendor security advisories.
   * Search bug bounty reports targeting similar platforms.
3. **Plan your attack:**
   * Decide if you'll focus on exploiting the core technology (0-day) or misconfigurations (common vulnerabilities).

**Necessary knowledge:**

* Basic understanding of web technologies (HTML, CSS, JavaScript).
* Familiarity with common CMS platforms (e.g., WordPress, Drupal, Joomla).
* Knowledge of how to search for and understand vulnerability reports.
* Ability to adapt your approach based on the identified technologies.

**Choosing your plan (0-day vs. Misconfigurations):**

* **0-day discovery:**
  * Requires advanced skills and knowledge of the specific technology.
  * More time-consuming and potentially less reliable.
  * High potential reward if successful.
* **Misconfigurations:**
  * Often easier to find, leveraging known vulnerabilities.
  * More consistent results but potentially lower bounties.
  * Good starting point for beginners.

**Ultimately, the best plan depends on your skills, available time, and comfort level.**



### <mark style="color:red;">Checking for Misconfigurations & Third-Party Vulnerabilities</mark>

**What it is:**

* This stage focuses on identifying security weaknesses in third-party libraries, plugins, or integrations used by the target product.
* It also involves understanding how the product itself handles vulnerabilities.

**Why it's important:**

* Third-party components often have known vulnerabilities that attackers can exploit.
* Misconfigurations in how the product integrates with third-party components can create security holes.
* Understanding the product's vulnerability handling helps determine potential attack vectors.

**What to do:**

1. **Setup and Exploration:**
   * Install the target product locally if possible (replicates the live environment).
   * Analyze the installation process for potential vulnerabilities.
   * Identify the web server type (traditional or modern routing) to tailor testing.
   * **Tools:**
     * Installation software (depends on the product).
     * Web server analysis tools (e.g., Apache logs for traditional servers).
2. **Third-Party Enumeration:**
   * Determine if the product integrates with third-party components.
   * Utilize tools and techniques (explained below) to identify them.
   * **Tools:**
     * Dependency scanners (e.g., npm audit for Node.js projects).
     * Browser developer tools to check for loaded scripts/libraries.
3. **Vulnerability Analysis:**
   * Research known vulnerabilities for the identified third-party components.
   * Test for those vulnerabilities in the context of the target product.
   * Analyze how the product handles potential vulnerabilities (e.g., sanitization, updates).
   * **Tools:**
     * Exploit databases (e.g., CVE Details).
     * Vulnerability scanners (specific to the identified components).
     * Web security scanners to identify common web vulnerabilities.
   * **Knowledge:**
     * Understanding of common web vulnerabilities (XSS, SQL Injection, etc.).
     * Familiarity with the identified third-party components (e.g., their security practices).
4. **Post-Exploitation Research:**
   * Go beyond vulnerability discovery and explore potential consequences.
   * Research how a vulnerability could be exploited in the context of the product.
   * **Knowledge:**
     * Basic understanding of post-exploitation techniques (e.g., privilege escalation).
     * Familiarity with the target product's architecture and functionality.
5. **Learn from Others:**
   * Read bug bounty reports targeting similar products.
   * Use these reports to identify common vulnerabilities and testing methodologies.
   * **Resources:**
     * Bug bounty platforms (e.g., HackerOne, Bugcrowd) often have public reports.

**Methodology Development:**

* Based on the product and its features, develop a specific testing methodology.
* This methodology should outline the steps you'll take for each stage mentioned above.
* Tailor your approach based on the identified web server type and third-party components.



### <mark style="color:red;">Sample Cases</mark>

### <mark style="color:purple;">WordPress</mark>

1. **WordPress Overview**:
   * WordPress is a popular open-source content management system (CMS) written in PHP and paired with a MySQL or MariaDB database.
   * It offers a plugin architecture and a template system (called Themes) that allows for customization and extension of its functionality.
2. **WordPress Registration**:
   * It's recommended to try registering with a `@company.tld` email address on the `/wp-register.php` page.
   * This can help identify potential vulnerabilities or misconfigurations related to the registration process.
3. **WordPress File and Directory Fuzzing**:
   * Extracting important WordPress files can be done through "backup fuzz" techniques.
   * Fuzzing the file and directory structure, including extensions like `.tar.gz`, `.zip`, `.7z`, `.phps`, `.php~`, `.sh`, and others, can help uncover hidden or sensitive files.
   * Additionally, fuzzing for dot files, such as `.env`, may reveal configuration details or sensitive information.
4. **Plugin and Theme Enumeration**:
   * Identifying the plugins and themes used in a WordPress installation is important, as they may have known vulnerabilities.
   * Reviewing the plugin and theme directories for potential issues or misconfigurations can help identify attack vectors.
5. **Automated Scanning**:
   * Tools like Burp Suite's Active Scan or Acunetix can be used to automate the scanning process and identify potential vulnerabilities in the WordPress installation.
6. **WordPress User Enumeration and Brute-Force Attacks**:
   * Attempting to enumerate WordPress users can be done by accessing the `/wp-json/wp/v2/users` endpoint or using the `/?author=1` parameter.
   * Brute-force attacks against user accounts can be conducted, but it's important to be mindful of the potential legal and ethical implications.
7. **WordPress REST API Enumeration**:
   * In addition to the `/wp-json/wp/v2/users` endpoint, you can also try enumerating other REST API endpoints, such as `/wp-json/wp/v2/posts` and `/wp-json/wp/v2/comments`.
   * Misconfigured or vulnerable REST API endpoints can expose sensitive information or allow unauthorized access.
8. **WordPress Login Brute-Force Protection**:
   * Many WordPress installations now have built-in protections against brute-force attacks on the login page.
   * Be aware of these security measures and understand how to bypass them, if necessary, while still respecting legal and ethical boundaries.

**Necessary Knowledge and Tools**:

* Basic understanding of web application security concepts, such as vulnerabilities, file inclusion, and authentication mechanisms.
* Familiarity with WordPress structure, file locations, and configuration files.
* Knowledge of web application testing methodologies, such as enumeration, fuzzing, and vulnerability scanning.
* Tools like Burp Suite, Acunetix, and automated web vulnerability scanners.
* Understanding of the legal and ethical boundaries when conducting security testing.

**Recommendations**:

1. Start with a test WordPress installation in a controlled environment to practice and experiment safely.
2. Familiarize yourself with the WordPress directory structure and configuration files.
3. Learn about common WordPress vulnerabilities and how to identify them.
4. Utilize automated scanning tools, but also perform manual testing and analysis.
5. Approach any testing or exploitation with caution and ensure you have the necessary permissions or authorization.
6. Stay up-to-date with the latest WordPress security advisories and best practices.



### <mark style="color:purple;">Fuzzing</mark>

1. **Fuzzing WordPress Plugins**:
   * Fuzzing plugins is a crucial step in identifying vulnerabilities within WordPress installations.
   * This involves systematically testing the plugins by providing various inputs, such as malformed data, unexpected parameters, or a large number of requests, to uncover potential security flaws.
   * Tools like WPScan, Wappalyzer, and Burp Suite can be used to enumerate and analyze installed WordPress plugins.
   * Key actions to perform:
     * Maintain an up-to-date database of known WordPress plugins and their versions.
     * Utilize fuzzing tools like Burp Suite Intruder or Zap Fuzzer to send malformed inputs to plugin endpoints and functionality.
     * Analyze the responses for potential vulnerabilities, such as code execution, SQL injection, or privilege escalation.
     * Carefully review the plugin source code for security issues, if possible.
     * Stay informed about the latest plugin vulnerabilities and security advisories.
2. **Fuzzing WordPress Themes**:
   * Fuzzing WordPress themes is similar to the process of fuzzing plugins, as themes can also contain security vulnerabilities.
   * Themes are responsible for the visual presentation and layout of a WordPress website, and they may include custom functionality or integrations that could be exploited.
   * Key actions to perform:
     * Maintain an up-to-date database of the latest WordPress theme slugs and versions.
     * Utilize tools like WPScan or custom scripts to enumerate the installed themes on a target WordPress site.
     * Fuzz the theme files and directories, including templates, stylesheets, and JavaScript files, for potential vulnerabilities.
     * Analyze the theme source code, if accessible, for security issues like insecure file inclusion, cross-site scripting (XSS), or SQL injection.
     * Stay informed about the latest theme vulnerabilities and security advisories.

**Necessary Knowledge and Tools**:

* Familiarity with web application security concepts, such as input validation, code injection, and privilege escalation.
* Understanding of WordPress plugin and theme architecture, file structure, and functionality.
* Knowledge of fuzzing techniques and tools, such as Burp Suite Intruder, ZAP Fuzzer, or custom-built scripts.
* Proficiency in programming languages like Python or Ruby for developing custom fuzzing scripts.
* Awareness of the latest WordPress plugin and theme vulnerabilities, security advisories, and best practices.



### <mark style="color:purple;">According to Codes</mark>

{% code overflow="wrap" %}
```python
from bs4 import BeautifulSoupimport urllib.request as hyperlinkimport oslink = hyperlink.urlopen('http://plugins.svn.wordpress.org/')wordPressSoup = BeautifulSoup(link,'lxml')filePath = os.path.dirname(os.path.realpath(__file__))fileNaming = (filePath + ('scrapedlist.txt'))print('The current working directory of the file is ' + filePath + ' the scraped list has been saved to this directory as scrapedlist.txt')with open('scrapedlist.txt', 'wt', encoding='utf8') as file:    for link in wordPressSoup.find_all('a', href=True):        lnk = link.get('href')        file.write(lnk.replace("/", "") + '\n')        print(lnk.replace("/", ""))
```
{% endcode %}

**Improved Approach for Fuzzing Plugins:**

1. **Targeted Approach:**
   * Identify specific plugins used by the target website through tools like WPScan or manual enumeration.
   * Focus fuzzing efforts on those identified plugins, reducing time and potential issues.
2. **Fuzzing Tools:**
   * Utilize dedicated fuzzing tools like WPaf or FFUF designed for WordPress security testing.
   * These tools allow crafting specific inputs and mutations to target plugin functionalities.
3. **Vulnerability Databases:**
   * Research known vulnerabilities associated with the identified plugins using databases like CVE Details or WPSec.
   * This helps prioritize fuzzing based on known weaknesses.
4. **Plugin Repositories:**
   * Access plugin details directly from official repositories like `WordPress.org` plugin directory (avoid scraping).
   * This ensures you're working with up-to-date information and respect terms of service.

**Necessary Knowledge:**

* **Understanding of WordPress plugins:** Basic knowledge of how plugins work and interact with WordPress.
* **Fuzzing concepts:** Familiarity with how fuzzing works to generate test cases and identify vulnerabilities.
* **WordPress security:** Awareness of common vulnerabilities in WordPress and plugins.
* **Bug bounty methodologies:** Understanding responsible disclosure practices and program guidelines.

**Additional Tips:**

* **Combine fuzzing with manual testing:** Analyze responses from fuzzing tools and manually explore potential vulnerabilities.
* **Stay updated:** Keep yourself informed about the latest WordPress vulnerabilities and plugin updates.



### <mark style="color:purple;">According to Codes</mark>

{% code overflow="wrap" %}
```python
from bs4 import BeautifulSoup
import urllib.request as hyperlink
import os

link = hyperlink.urlopen('https://themes.svn.wordpress.org/')
wordPressSoup = BeautifulSoup(link,'lxml')
filePath = os.path.dirname(os.path.realpath(__file__))
fileNaming = (filePath + ('scrapedlist.txt'))
print('The current working directory of the file is ' + filePath + ' the scraped list has been saved to this directory as scrapedlist.txt')
with open('scrapedlist.txt', 'wt', encoding='utf8') as file:
    for link in wordPressSoup.find_all('a', href=True):
        lnk = link.get('href')
        file.write(lnk.replace("/", "") + '\n')
        print(lnk.replace("/", ""))
```
{% endcode %}

**Explanation of the Code:**

This code snippet scrapes theme names from the WordPress theme directory:

1. **Imports:**
   * `from bs4 import BeautifulSoup`: Imports a library for parsing HTML content.
   * `import urllib.request as hyperlink`: Imports a library for making web requests (insecure for modern practices).
   * `import os`: Provides functionalities for interacting with the operating system.
2. **Fetching Theme Directory:**
   * `link = hyperlink.urlopen('https://themes.svn.wordpress.org/')`: Opens the WordPress theme directory (using an insecure method).
3. **Parsing HTML:**
   * `wordPressSoup = BeautifulSoup(link,'lxml')`: Parses the downloaded HTML content using BeautifulSoup with the lxml parser.
4. **Saving Directory:**
   * `filePath = os.path.dirname(os.path.realpath(__file__))`: Gets the directory where the script is located.
   * `fileNaming = (filePath + ('scrapedlist.txt'))`: Defines the filename for storing scraped links.
5. **Writing Scraped Links:**
   * Opens the file "scrapedlist.txt" for writing in text mode with UTF-8 encoding.
   * Iterates over all anchor tags (`<a>`) with `href` attributes in the parsed HTML.
   * Extracts the link URL, removes leading slashes, and writes it to the file with a newline character.

**Why This Isn't Ideal for Bug Bounty Hunting:**

* **Inefficiency:** Scraping the entire theme directory is unnecessary and time-consuming.
* **Security:** Directly accessing WordPress repositories might violate their terms of service. Using `urllib.request` is considered insecure for modern practices. Consider using libraries like `requests`.
* **Outdated Technique:** More efficient and secure methods exist for identifying themes used on a target website.

**Necessary Knowledge:**

* **Understanding of WordPress themes:** Basic knowledge of how themes work and interact with WordPress.
* **WordPress security:** Awareness of common vulnerabilities in WordPress and themes.
* **Bug bounty methodologies:** Understanding responsible disclosure practices and program guidelines.
* **Web scraping ethics:** Respecting terms of service and avoiding scraping practices that could overload servers.



### <mark style="color:purple;">**Django**</mark>

1. **Django Overview**:
   * Django is a popular Python-based free and open-source web framework that follows the Model-Template-View (MTV) architectural pattern.
   * It is maintained by the Django Software Foundation, an independent organization established in the US as a 501 non-profit.
2. **Django Security Methodology**:
   * **XSS (Cross-Site Scripting) or CRLF (Carriage Return Line Feed) Discovery**: Look for opportunities to overwrite the CSRF token by discovering XSS or CRLF vulnerabilities on the `.domain.tld` endpoint.
   * **XSS Testing**: Django's built-in protection against XSS can be effective, but it's still important to test for potential XSS vulnerabilities, especially in areas like `<a>`, `<form>`, and `<iframe>` tags where user input may be reflected.
   * **IDOR (Insecure Direct Object Reference), SSTI (Server-Side Template Injection), and Logic-based Vulnerabilities**: Identify and test for these types of vulnerabilities, which can be present in Django applications.
   * **Endpoint Fuzzing**: Fuzz the application to discover endpoints that may not be obvious from the file or directory structure.
   * **Reverse Proxy Configuration**: If the Django application is behind a reverse proxy, there may be an additional path that could point to a different location.
   * **Debug Mode Discovery**: Check if the application is running in debug mode, as this can expose sensitive information.
   * **Host Header Manipulation**: Try changing the Host header to see if the application behaves differently.
   * **Verb Tampering**: Test the application's behavior by sending different HTTP request methods (e.g., POST, PUT, DELETE) to various endpoints.
   * **Admin Login Brute-Force**: Send a POST request to the `/admin/login/?next=/admin/` endpoint and look for a 500 status code, which may indicate a potential vulnerability.
   * **404 Page Analysis**: Send requests to the 404 page and analyze the response for any useful information or potential vulnerabilities.
   * **Automated Scanning**: Use tools like Burp Suite's Active Scan or Acunetix to automatically scan the Django application for known vulnerabilities.

**Necessary Knowledge and Tools**:

* Strong understanding of web application security concepts, such as input validation, authentication, authorization, and common vulnerabilities.
* Familiarity with the Django framework, its architecture, and the Model-Template-View (MTV) pattern.
* Knowledge of Python programming language and Django-specific features, such as templates, middleware, and URL routing.
* Proficiency in using web application security testing tools, such as Burp Suite, OWASP ZAP, and custom-built scripts.
* Understanding of HTTP protocol, request methods, and header manipulation.
* Knowledge of common web application vulnerabilities, such as XSS, IDOR, SSTI, and logic-based flaws.

**Recommendations**:

1. Set up a test Django environment to practice and experiment with security testing safely.
2. Familiarize yourself with the Django documentation, including the security guide and best practices.
3. Stay up-to-date with the latest Django security advisories and vulnerabilities.
4. Develop a methodical approach to testing Django applications, covering the areas mentioned above.
5. Utilize a combination of automated scanning tools and manual testing to thoroughly assess the security of the Django application.
6. Document your findings, report any vulnerabilities responsibly, and follow the appropriate disclosure process.
7. Continuously learn and expand your knowledge of web application security, as the landscape is constantly evolving.



### <mark style="color:purple;">**Laravel**</mark>

1. **Laravel Overview**:
   * Laravel is a popular PHP-based free and open-source web framework that follows the Model-View-Controller (MVC) architectural pattern.
   * It is one of the most widely used web frameworks for building modern PHP applications.
2. **Laravel Security Methodology**:
   * **XSS (Cross-Site Scripting) or CRLF (Carriage Return Line Feed) Discovery**: Look for opportunities to overwrite the CSRF token by discovering XSS or CRLF vulnerabilities on the `.domain.tld` endpoint.
   * **XSS Testing**: Laravel's built-in protection against XSS can be effective, but it's still important to test for potential XSS vulnerabilities, especially in areas like `<a>`, `<form>`, and `<iframe>` tags where user input may be reflected.
   * **`.env` File Exposure**: The `.env` file in Laravel typically stores sensitive information, such as database credentials and API keys. While it is not stored in the public directory, it's important to check for any potential exposure of this file.
   * **IDOR (Insecure Direct Object Reference) and Logic-based Vulnerabilities**: Identify and test for these types of vulnerabilities, which can be present in Laravel applications.
   * **File and Directory Fuzzing**: Laravel uses a traditional web server with a `public` folder as the document root, fuzz for files, and directories to discover potential vulnerabilities.
   * **Endpoint Enumeration**: Look for the `_ignition/health-check` endpoint and check if the `can_execute_commands` feature is enabled, as this could lead to potential Remote Code Execution (RCE) vulnerabilities.
   * **Debug Mode and Verb Tampering**: Check if the application is running in debug mode, as this can expose sensitive information. Also, test the application's behavior by sending different HTTP request methods (e.g., POST, PUT, DELETE) to various endpoints.
   * **Information Disclosure via Arrays**: Use arrays instead of strings in some cases, as this may result in information disclosure vulnerabilities.
   * **Automated Scanning**: Use tools like Burp Suite's Active Scan or Acunetix to automatically scan the Laravel application for known vulnerabilities.
   * **Header-based Attacks**: In Laravel versions ≤ 8.x, the `X-Forwarded-Host` header could be used by an attacker to generate a malicious password-reset email.

**Necessary Knowledge and Tools**:

* Strong understanding of web application security concepts, such as input validation, authentication, authorization, and common vulnerabilities.
* Familiarity with the Laravel framework, its architecture, and the Model-View-Controller (MVC) pattern.
* Knowledge of PHP programming language and Laravel-specific features, such as routing, middleware, and Eloquent ORM.
* Proficiency in using web application security testing tools, such as Burp Suite, OWASP ZAP, and custom-built scripts.
* Understanding of HTTP protocol, request methods, and header manipulation.
* Knowledge of common web application vulnerabilities, such as XSS, IDOR, and logic-based flaws.

**Recommendations**:

1. Set up a test Laravel environment to practice and experiment with security testing safely.
2. Familiarize yourself with the Laravel documentation, including the security guide and best practices.
3. Stay up-to-date with the latest Laravel security advisories and vulnerabilities.
4. Develop a methodical approach to testing Laravel applications, covering the areas mentioned above.
5. Utilize a combination of automated scanning tools and manual testing to thoroughly assess the security of the Laravel application.
6. Document your findings, report any vulnerabilities responsibly, and follow the appropriate disclosure process.
7. Continuously learn and expand your knowledge of web application security, as the landscape is constantly evolving.



### <mark style="color:purple;">Sample Methodology for React or VueJS</mark>

Penetration testing, a critical component of cybersecurity and bug bounty programs, involves simulating real-world attacks to identify and address vulnerabilities in software applications. For React and VueJS applications, a structured methodology ensures thorough testing and enhances application security. Below is a suggested methodology tailored for both React and VueJS applications, incorporating insights from the provided sources.

#### 1. Preparation and Planning

* **Understand Application Architecture**: Begin by gaining a deep understanding of the application's architecture, including both the client-side and server-side components. For React applications, this involves understanding the component hierarchy and state management mechanisms. For VueJS, focus on the reactivity system and the use of Vuex for state management.
* **Scope Definition**: Clearly define the scope of the penetration test, including the specific functionalities and components to be tested. This helps in focusing the efforts on critical areas of the application.

#### 2. Reconnaissance

* **Gather Information**: Collect as much information as possible about the application and its environment. This includes understanding the libraries and dependencies used, as React and VueJS applications often rely on third-party libraries which could introduce vulnerabilities.
* **Identify Entry Points**: Identify all possible entry points into the application, including forms, APIs, and any other interfaces that accept user input.

#### 3. Vulnerability Assessment

* **Automated Scanning**: Use automated tools to scan the application for known vulnerabilities, especially focusing on common issues like Cross-Site Scripting (XSS) and Cross-Site Request Forgery (CSRF) which are prevalent in client-side applications.
* **Manual Testing and Code Review**: Perform manual testing and code review to identify vulnerabilities that automated tools might miss. Pay special attention to custom code and components, as these are often less scrutinized than library code.

#### 4. Exploitation

* **Attempt Exploits**: Safely attempt to exploit identified vulnerabilities to assess their impact. This step is crucial for understanding the real-world implications of each vulnerability.
* **Document Findings**: Keep detailed records of the exploitation attempts, including the methods used and the outcomes.

#### 5. Reporting and Remediation

* **Report Findings**: Compile a comprehensive report detailing the vulnerabilities found, their potential impact, and recommendations for remediation. Prioritize the vulnerabilities based on their severity and potential impact.
* **Remediation Guidance**: Provide specific guidance on how to address each identified vulnerability. For React and VueJS applications, this often involves updating dependencies, implementing proper input validation and output encoding, and adopting secure coding practices.

#### 6. Re-Testing and Follow-Up

* **Verify Fixes**: After the development team has addressed the vulnerabilities, perform a re-test to ensure that the fixes are effective and that no new vulnerabilities have been introduced.
* **Continuous Monitoring**: Encourage the adoption of regular security audits and penetration testing as part of the development lifecycle to identify and mitigate new vulnerabilities as they arise.

#### Best Practices

* **Engage Experienced Penetration Testers**: Work with skilled professionals who have expertise in React and VueJS application security.
* **Stay Updated**: Keep abreast of the latest security advisories, patches, and best practices for React and VueJS.
* **Secure Coding Practices**: Implement secure coding practices from the outset, including input validation, output encoding, and proper authentication and authorization mechanisms.



#### Code Snippet Example

Here is an example of how an XSS vulnerability might be exploited in a React application:

```javascript
const payload = '<script>alert("XSS!");</script>';
const input = document.getElementById('input');
input.value = payload;
```

In this example, the `payload` variable contains a malicious JavaScript payload that will be executed when rendered by the browser. The `input` variable is a reference to an input field, and the `value` property is set to the `payload` value. This will cause the payload to be injected into the input field when the user submits the form.



### <mark style="color:yellow;">Extra</mark>

Advanced Recon & Web Application Discovery

<figure><img src=".gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" lineNumbers="true" %}
```
Recon-ng - A full-featured reconnaissance framework.
httpx - A fast and multi-purpose HTTP toolkit.
isup.sh - A tool to check whether a website is up or down from various locations.
Arjun - A tool to find hidden parameters in URLs.
jSQL - A SQL injection tool for automatic exploitation.
Smuggler - A smuggling detection and exploitation tool.
Sn1per - An automated scanner to find security vulnerabilities.
Spiderfoot - An open-source intelligence (OSINT) automation tool.
Nuclei - A fast and customizable vulnerability scanner.
Jaeles - A framework for testing and exploiting vulnerabilities in web applications.
ChopChop - A security testing tool to exploit XSS via different methods.
Inception - A network-based Android penetration testing suite.
Eyewitness - A tool to take screenshots of web pages.
Meg - A tool to fetch many paths from a web server.
Gau - Get All Urls - A tool to extract URLs from the wayback machine.
Snallygaster - A tool to scan for secret files on HTTP servers.
NMAP - A powerful network discovery and security auditing tool.
Waybackurls - A tool to fetch all the URLs that the wayback machine knows for a domain.
Gotty - A simple command-line tool to turn your CLI tools into web applications.
GF - A wrapper around grep to extract and manipulate data.
GF Patterns - A collection of useful patterns for the GF (grep-friendly) tool.
Paramspider - A tool to enumerate web parameters and spider a target more effectively.
XSSER - A tool for automatic XSS vulnerability detection.
UPDOG - A quick and simple file hosting service.
JSScanner - A tool to find JavaScript files on a target and scan them for endpoints.
Takeover - A tool to detect subdomain takeover vulnerabilities.
Keyhacks - A tool for finding exposed API keys on GitHub.
S3 Bucket AIO Pwn - A tool to find and exploit S3 buckets.
BHEH Sub Pwner Recon - A subdomain takeover reconnaissance tool.
GitLeaks - A tool to find secrets and sensitive files in Git repositories.
Domain-2IP-Converter - A tool to convert domain names to IP addresses.
Dalfox - A fast parameter analysis and XSS scanner.
Log4j Scanner - A scanner for the Log4j vulnerability.
Osmedeus - A fully automated tool to collect and analyze attack data.
getJS - A tool to find JavaScript files on a website and gather information about them.
Amass - An open-source tool to help information security professionals perform network mapping.
```
{% endcode %}



### Tools Wrap-up&#x20;

#### **OSINT (Open Source Intelligence)**

* **OSINT Framework:** Collects information from a variety of online sources, including social media, websites, and databases.
* <mark style="background-color:blue;">**theHarvester**</mark>**:** Gathers email addresses, phone numbers, and other contact information from websites and social media profiles.
* **Gau:** Discovers subdomains and virtual hosts associated with a target domain.
* **Arjun:** Extracts sensitive information, such as passwords and API keys, from public code repositories.
* <mark style="background-color:blue;">**Amass**</mark>**:** Enumerates subdomains and performs reverse DNS lookups.
* **Recon-ng:** A modular reconnaissance framework that can perform a variety of tasks, including OSINT gathering, network scanning, and vulnerability assessment.
* <mark style="background-color:blue;">**Spiderfoot**</mark>**:** Collects information about a target from a variety of online sources, including social media, websites, and databases.
* **Maltego:** A powerful data mining and visualization tool that can be used to investigate relationships between people, organizations, and other entities.
* **intelx website - https://intelx.io/:** Provides access to a database of leaked and compromised data, including email addresses, passwords, and other sensitive information.
* **bgp website - https://bgp.he.net:** Provides information about the Border Gateway Protocol (BGP), which is used to route traffic on the Internet. This information can be used to identify potential attack paths and vulnerabilities.
* **search whois - https://whois.arin.net/ui/:** Provides information about the ownership and registration of domain names. This information can be used to identify the owner of a website or to track down the source of an attack.
* **website search - https://www.yougetsignal.com/:** Provides information about the technologies used on a website, including the web server, programming languages, and content management system. This information can be used to identify potential vulnerabilities and to develop targeted attacks.
* **Netcraft website - https://searchdns.netcraft.com/:** Provides information about the security and performance of websites. This information can be used to identify potential vulnerabilities and to track down the source of an attack.
* **Netcraft - https://sitereport.netcraft.com/:** Provides detailed reports on the security and performance of websites. This information can be used to identify potential vulnerabilities and to develop targeted attacks.
* **BuiltWith: https://builtwith.com/:** Provides information about the technologies used on a website, including the web server, programming languages, and content management system. This information can be used to identify potential vulnerabilities and to develop targeted attacks.
* **Wappalyzer: https://www.wappalyzer.com/:** Provides information about the technologies used on a website, including the web server, programming languages, and content management system. This information can be used to identify potential vulnerabilities and to develop targeted attacks.
* **Rescan: https://rescan.io/:** Provides information about the security and performance of websites. This information can be used to identify potential vulnerabilities and to track down the source of an attack.
* **PageXRay: https://pagexray.com/:** Provides information about the technologies used on a website, including the web server, programming languages, and content management system. This information can be used to identify potential vulnerabilities and to develop targeted attacks.
* **WhatRuns: https://www.whatruns.com/:** Provides information about the technologies used on a website, including the web server, programming languages, and content management system. This information can be used to identify potential vulnerabilities and to develop targeted attacks.

#### **Network Scanning**

* **Nmap:** A powerful network scanner that can be used to discover hosts, ports, and services on a network.
* **Shodan:** A search engine for Internet-connected devices. Shodan can be used to find and exploit vulnerabilities in devices such as routers, webcams, and industrial control systems.
* **Censys:** A search engine for Internet-connected devices that provides more detailed information than Shodan. Censys can be used to find and exploit vulnerabilities in devices such as routers, webcams, and industrial control systems.
* **Subfinder:** A tool that discovers subdomains associated with a target domain. This information can be used to identify potential attack paths and vulnerabilities.
* **Trufflehog:** A tool that searches for secrets, such as passwords and API keys, in public code repositories. This information can be used to compromise accounts and systems.
* **Gobuster:** A tool that performs brute-force attacks against web applications to discover hidden directories and files. This information can be used to identify potential vulnerabilities and to develop targeted attacks.
* **dnscan:** A tool that performs DNS reconnaissance to discover subdomains, MX records, and other information associated with a target domain. This information can be used to identify potential attack paths and vulnerabilities.
* **Spoofcheck:** A tool that checks for DNS spoofing vulnerabilities. DNS spoofing is a technique that can be used to redirect traffic to a malicious website.
* **Sn1per:** A tool that performs network reconnaissance to discover open ports and services on a target network. This information can be used to identify potential attack paths and vulnerabilities.
* **Nikto:** A web vulnerability scanner that can be used to identify vulnerabilities in web applications.
* <mark style="background-color:blue;">**AssetFinder**</mark>**:** A tool that discovers assets, such as hosts, subdomains, and email addresses, associated with a target organization. This information can be used to identify potential attack paths and vulnerabilities.
* **dnsrecon:** A tool that performs DNS reconnaissance to discover subdomains, MX records, and other information associated with a target domain. This information can be used to identify potential attack paths and vulnerabilities.
* **Knockpy:** A tool that performs network reconnaissance to discover open ports and services on a target network. This information can be used to identify potential attack paths and vulnerabilities.
* **SubBrute:** A tool that performs brute-force attacks against subdomains to discover hidden subdomains. This information can be used to identify potential attack paths and vulnerabilities.
* **altdns:** A tool that performs DNS reconnaissance to discover alternative DNS servers for a target domain. This information can be used to bypass DNS filtering and to launch attacks from different locations.
* **EyeWitness:** A tool that takes screenshots of websites and web applications. This information can be used to document the appearance of a website or web application before and after an attack.
* **Zscanner - https://github.com/zseano/InputScanner:** A tool that scans for vulnerabilities in web applications.
* **dnsX:** A tool that performs DNS reconnaissance to discover subdomains, MX records, and other information associated with a target domain. This information can be used to identify potential attack paths and vulnerabilities.

#### **Vulnerability Scanning**

* **Burp Suite:** A powerful web application security scanner that can be used to identify vulnerabilities in web applications.
* **Wafw00f:** A tool that identifies web application firewalls (WAFs). WAFs can be used to protect web applications from attacks.
* **FFuF:** A tool that performs brute-force attacks against web applications to discover hidden directories and files. This information can be used to identify potential vulnerabilities and to develop targeted attacks.

#### **Web Application Scanning**

* **GAU (Get All Urls) - https://github.com/lc/gau:** A tool that discovers all URLs on a website. This information can be used to identify potential attack paths and vulnerabilities.
* **Crawley - https://github.com/s0rg/crawley:** A tool that crawls websites to discover hidden content and vulnerabilities.
* **GoSpider - https://github.com/jaeles-project/gospider:** A tool that crawls websites to discover hidden content and vulnerabilities.
* <mark style="background-color:blue;">**HTTPX**</mark> - is particularly well-suited for reconnaissance because it can be used to quickly and easily gather information about a target website or web application

#### **Certificate Checking**

* **checking certificate - https://crt.sh/:** A website that provides information about SSL/TLS certificates. This information can be used to identify vulnerabilities in SSL/TLS implementations.
* **checking ssl/tls - https://github.com/nabla-c0d3/sslyze:** A tool that checks SSL/TLS certificates for vulnerabilities.

#### **Other**

* **google dork:** A search query that can be used to find specific information on the web. Google dorks can be used to find vulnerabilities, sensitive information, and other information that can be useful for attackers.
* **Dirsearch:** A tool that performs brute-force attacks against web directories to discover hidden directories. This information can be used to identify potential vulnerabilities and to develop targeted attacks.
* <mark style="background-color:blue;">**Sublist3r**</mark>**:** A tool that discovers subdomains associated with a target domain. This information can be used to identify potential attack paths and vulnerabilities.
* **https://archive.org/web/:** A website that archives web pages. This website can be used to find older versions of websites and web pages that may contain vulnerabilities.
* **https://www.exploit-db.com/:** A website that provides a database of exploits. This website can be used to find exploits for vulnerabilities that have been identified.
* **https://inteltechniques.com/tools/index.html:** A website that provides a list of tools and resources for intelligence gathering and analysis.
* <mark style="background-color:blue;">**WFuzz**</mark>**:** A tool that performs fuzzing attacks against web applications to discover vulnerabilities.
* **Scrapy:** A tool that can be used to scrape data from websites. This data can be used to identify potential attack paths and vulnerabilities.



### Bug Hunting Workflow in 10 Steps:

1. **Target Selection:** Choose a bug bounty program based on your interests and skills. Read and understand the program rules thoroughly.
2. **Initial Enumeration (Subfinder, Amass):** Discover subdomains associated with the target program.
3. **Further Enumeration (theHarvester):** Gather additional information like email addresses and phone numbers from social media and other online sources. (Optional: Use Recon-ng to automate some of these processes)
4. **Network Scanning (Nmap):** Identify IP addresses and services running on the target network.
5. **Analyze Technologies (passive methods):** Use website search tools (not listed) to see what technologies the website uses (e.g., programming languages, CMS). This can provide clues for finding vulnerabilities.
6. **Manual Testing with Burp Suite:** Start a manual web application penetration test using Burp Suite to identify potential vulnerabilities.
7. **Refine Enumeration Based on Findings (Optional):** If you find vulnerabilities related to specific functionalities, use tools like GAU, Crawly, or GoSpider to discover all related URLs for further testing.
8. **Verify and Exploit (Ethical Hacking):** If you find a potential vulnerability, research and verify its exploitability before reporting it. Do not exploit vulnerabilities beyond testing to confirm functionality (illegal and unethical).
9. **Report Findings:** Write a clear and concise report following the program's guidelines, documenting your steps and the impact of the vulnerability.
10. **Follow-up:** Maintain communication with the program coordinators and address any questions they may have about your report.

