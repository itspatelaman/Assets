    ___
| Feature                | Active Reconnaissance                          | Passive Reconnaissance                       |
|------------------------|-----------------------------------------------|---------------------------------------------|
| **Definition**         | Directly interacting with the target to gather information. | Indirectly gathering information without interacting with the target. |
| **Interaction**        | Requires direct engagement with the target system or network. | No direct engagement with the target system or network. |
| **Tools Used**         | Tools like Nmap, Metasploit, Nikto, and Nessus. | Tools like Shodan, Google Dorking, WHOIS, and social media. |
| **Detection Risk**     | High risk of detection as it generates logs on the target. | Low risk of detection as it avoids direct contact with the target. |
| **Purpose**            | Identifies specific vulnerabilities in the target. | Gathers publicly available information for initial analysis. |
| **Examples**           | - Port scanning<br>- Vulnerability scanning<br>- Sending probes to services. | - DNS lookup<br>- Analyzing job postings<br>- Reviewing leaked data. |
| **Legal Implications** | More likely to require legal permissions as it involves direct probing. | Generally considered legal as it relies on open-source intelligence (OSINT). |
| **Use Case**           | Used in penetration testing after passive reconnaissance. | Used in the initial phase of reconnaissance to avoid alerting the target. |

___
# Information Gathered in Footprinting

Footprinting is the initial phase of ethical hacking, where information about a target system, organization, or network is collected. The gathered information is classified into several categories:

---

## 1. **Network Information**
   - **IP Address Ranges**: Identifying the range of IP addresses used by the organization.
   - **DNS Information**: Domain names, subdomains, and DNS zone data.
   - **Network Block Information**: Finding network blocks assigned to the organization.
   - **Traceroute Data**: Understanding the network path to the target.
   - **ISP Details**: Internet Service Providers hosting the target.

---

## 2. **System Information**
   - **Operating Systems**: Identifying the OS used on servers and endpoints.
   - **Open Ports**: Determining accessible ports and services.
   - **Service Versions**: Gathering information about software versions running on the system.
   - **Hostnames**: Resolving and identifying associated hostnames.

---

## 3. **Organizational Information**
   - **Employee Details**: Names, roles, emails, and social media profiles of employees.
   - **Internal Contacts**: Email IDs, phone numbers, and organizational structure.
   - **Office Locations**: Physical addresses of offices and data centers.
   - **Job Postings**: Insights into technologies used, internal tools, and processes.

---

## 4. **Website Information**
   - **Domain Details**: WHOIS information, domain registration, and expiry details.
   - **Website Technologies**: CMS platforms, frameworks, plugins, and backend tech.
   - **Metadata**: Extracting metadata from documents or images (EXIF data).
   - **Sitemap Analysis**: Crawling website directories and files.

---

## 5. **Security Posture**
   - **Firewall and IDS**: Detecting the presence of firewalls or intrusion detection systems.
   - **SSL/TLS Information**: Checking for HTTPS configuration and certificate details.
   - **Vulnerabilities**: Early identification of exposed weaknesses.

---

## 6. **Publicly Available Information**
   - **Social Media**: Posts, hashtags, announcements revealing sensitive information.
   - **Public Repositories**: Code repositories (GitHub, GitLab) revealing credentials or configurations.
   - **News and PR**: Articles or announcements revealing partnerships or technologies.
   - **Leaked Data**: Searching for leaked credentials or documents on the dark web.

---

## 7. **Tools and Techniques for Footprinting**
   - **Search Engines**: Google Dorking, Bing, and other advanced search techniques.
   - **Online Tools**: WHOIS lookup, Shodan, Maltego, and Netcraft.
   - **Network Scanners**: Nmap, Angry IP Scanner.
   - **Social Media Tools**: LinkedIn, Twitter, Facebook.
   - **DNS Tools**: Dig, nslookup, and DNSRecon.

---

Footprinting provides a foundation for further reconnaissance by mapping the target's digital and physical landscape.
<br><br>

# Footprinting Methodology

The methodology involves a structured approach to gathering information about a target. Below is a flowchart-like representation:

---

## Step 1: Define Objectives
   - What information is required?
   - What tools and methods will be used?
   - Legal permissions (if necessary).

---

## Step 2: Information Gathering

### 2.1 Passive Footprinting
   - Gather public information without interacting with the target.
   - Tools and Techniques:
     - **WHOIS Lookup**: Identify domain owner, registrar, and contact details.
     - **Search Engines**: Google Dorking, advanced search queries.
     - **Social Media**: LinkedIn, Twitter, Facebook for employee or organizational insights.
     - **Public Repositories**: GitHub, Bitbucket for code or credentials leaks.
     - **DNS Enumeration**: nslookup, dig for domain records.

---

### 2.2 Active Footprinting
   - Interact directly with the target system or network.
   - Tools and Techniques:
     - **Port Scanning**: Nmap for identifying open ports and services.
     - **Traceroute**: Mapping the path to the target network.
     - **Service Enumeration**: Identifying software running on ports (e.g., SSH, HTTP).
     - **Web Application Analysis**: Crawling and analyzing web technologies.

---

## Step 3: Categorize Data
   - **Network Information**:
     - IP ranges, subnets, and DNS information.
   - **System Information**:
     - Operating systems, server versions, and vulnerabilities.
   - **Organizational Information**:
     - Employee names, emails, and internal structure.

---

## Step 4: Analyze Vulnerabilities
   - Use collected data to identify:
     - Exposed ports and services.
     - Misconfigurations in systems.
     - Potential attack vectors.

---

## Step 5: Document Findings
   - Create a structured report with:
     - Information gathered.
     - Tools and methods used.
     - Observations and vulnerabilities identified.

---
<br><br>
# Footprinting Methodology Flowchart

- **Footprinting Techniques**
    - **Footprinting through Search Engines**
        - Advanced Google Hacking Techniques
        - Google Hacking Database
        - SHODAN Search Engine
    - **Footprinting through Internet Research Services**
        - People Search Services
        - Financial Services and Job Sites
        - archive.org
        - Competitive Intelligence and Business Profile Sites
    - **Footprinting through Social Networking Sites**
        - Social Media Sites
        - Analyze Social Network Graphs
        - Groups, Forums, and Blogs
        - Dark Web Searching Tools
    - **Whois Footprinting**
        - Whois Lookup
        - IP Geolocation Lookup
    - **DNS Footprinting**
        - DNS Interrogation
        - Reverse DNS Lookup
    - **Network and Email Footprinting**
        - Traceroute
        - Track Email Communication
    - **Footprinting through Social Engineering**
        - Eavesdropping
        - Shoulder Surfing
        - Dumpster Diving
        - Impersonation
---
<br><br>

# Footprinting Using Advanced Google Hacking Techniques

## What is Google Hacking?
Google Hacking refers to using **advanced search queries** (also called **Google Dorks**) to uncover sensitive information or resources that are unintentionally exposed on the web.

It helps in gathering:
- Sensitive files (PDFs, DOCs, etc.)
- Admin login pages
- Database details
- Misconfigured servers
- Exposed usernames and passwords

---

## Key Google Operators for Footprinting

1. **`site:`**  
   - Limits search results to a specific domain.  
   - **Example:** `site:example.com`  
     - Finds all indexed pages of `example.com`.

2. **`filetype:`**  
   - Searches for specific file types (PDF, DOCX, TXT, etc.).  
   - **Example:** `filetype:pdf site:example.com`  
     - Finds all PDF files hosted on `example.com`.

3. **`intitle:`**  
   - Searches for specific keywords in the title of web pages.  
   - **Example:** `intitle:"index of" site:example.com`  
     - Finds directory listings or indexes of a website.

4. **`inurl:`**  
   - Searches for specific words or directories in the URL.  
   - **Example:** `inurl:admin site:example.com`  
     - Finds URLs containing "admin" on `example.com`.

5. **`cache:`**  
   - Displays the cached version of a website.  
   - **Example:** `cache:example.com`  
     - Shows Google’s cached copy of `example.com`.

6. **`link:`** *(Deprecated)*  
   - Finds external pages linking to a specific website.  
   - **Example:** `link:example.com`

7. **`related:`**  
   - Finds websites similar to the specified domain.  
   - **Example:** `related:example.com`

8. **`allintext:` / `intext:`**  
   - Searches for specific text within the page content.  
   - **Example:** `allintext:password filetype:txt`

---

## Common Google Dork Examples

| **Google Dork**                           | **Purpose**                                  |
|-------------------------------------------|---------------------------------------------|
| `site:example.com filetype:log`           | Search for log files on a target domain.    |
| `intitle:"index of" passwords`            | Find directories containing passwords.      |
| `inurl:wp-admin site:example.com`         | Locate WordPress admin pages.               |
| `filetype:sql site:example.com`           | Discover database dumps.                    |
| `allintext:password filetype:txt`         | Search for plaintext password files.        |
| `site:example.com "username" "password"`  | Search for exposed credentials.             |
| `cache:example.com`                       | View cached versions of target pages.       |

---

## Tools to Automate Google Hacking

1. **Google Hacking Database (GHDB)**  
   - A collection of pre-made Google Dorks.  
   - Maintained by Offensive Security: [exploit-db.com/google-hacking-database](https://www.exploit-db.com/google-hacking-database)

2. **SearchSploit**  
   - Local command-line access to GHDB queries.  

3. **Automated Tools**  
   - **Googler** (Linux CLI tool)  
   - **GooDork** (Python-based Google Dorking tool)  
   - **GHunt** (Advanced tool for footprinting Gmail accounts)  

---

## Practical Steps

1. Identify the target domain (e.g., `example.com`).
2. Use advanced Google queries to uncover:
   - Sensitive files  
   - Admin pages  
   - Open directories  
   - Cached or forgotten content  
3. Record the findings for further analysis.

---

## Conclusion

Advanced Google Hacking is a critical part of the **footprinting phase**. By leveraging Google search operators and dorks, penetration testers can efficiently gather **publicly exposed data** and identify misconfigurations.

---

### Key References:
- [Google Hacking Database (GHDB)](https://www.exploit-db.com/google-hacking-database)
- Tools: `Googler`, `GooDork`, `SearchSploit`
---
<br><br>
# Google Hacking Database (GHDB)

## What is the Google Hacking Database (GHDB)?

The **Google Hacking Database (GHDB)** is a collection of **predefined search queries** (Google Dorks) that help security professionals uncover **sensitive information** exposed on the internet through **search engines**.

- **Maintained by**: [Exploit-DB](https://www.exploit-db.com/google-hacking-database)  
- **Created by**: Johnny Long  
- **Purpose**: Identify information unintentionally exposed due to misconfigurations, insecure files, or improper indexing.  

---

## Why Use GHDB?

GHDB allows penetration testers, ethical hackers, and bug bounty hunters to:
- Discover **sensitive information** such as usernames, passwords, and database dumps.
- Identify **exposed directories**, admin panels, and login pages.
- Detect **vulnerable applications** and outdated software.
- Perform **reconnaissance** during the footprinting phase.

---

## Categories in GHDB

GHDB queries are categorized based on the type of information they retrieve:

1. **Files Containing Juicy Info**  
   - Sensitive files (PDFs, DOCs, TXT, etc.) with passwords or other private content.  
   - **Example:** `filetype:txt intext:password`

2. **Files Containing Passwords**  
   - Files storing usernames, passwords, or credentials.  
   - **Example:** `filetype:log intext:password`

3. **Sensitive Directories**  
   - Misconfigured or open directories with accessible files.  
   - **Example:** `intitle:"index of" site:example.com`

4. **Web Server Detection**  
   - Identify versions of web servers or applications running on a target.  
   - **Example:** `inurl:phpinfo.php`

5. **Error Messages**  
   - Web pages that expose database errors, code structures, or debug information.  
   - **Example:** `intext:"mysql error" site:example.com`

6. **Vulnerable Servers**  
   - Search for outdated or vulnerable versions of software.  
   - **Example:** `inurl:wp-login.php version`

7. **Login Pages**  
   - Locate login panels and admin dashboards for applications or websites.  
   - **Example:** `inurl:admin site:example.com`

8. **Network or Vulnerability Data**  
   - Uncover network information, router configurations, and device vulnerabilities.  
   - **Example:** `inurl:".env" filetype:env`

---

## Example Google Dorks from GHDB

| **Purpose**                          | **Google Dork Query**                         |
|--------------------------------------|----------------------------------------------|
| Search for admin login pages         | `inurl:admin site:example.com`               |
| Find open directories                | `intitle:"index of" site:example.com`        |
| Discover password files              | `filetype:txt intext:password`               |
| Locate SQL database files            | `filetype:sql site:example.com`              |
| Find environment files               | `inurl:.env filetype:env`                    |
| Search for error messages            | `intext:"mysql error" site:example.com`      |
| Find exposed PDF files               | `filetype:pdf site:example.com`              |
| Detect WordPress login pages         | `inurl:wp-login.php`                         |

---

## How to Use GHDB in Reconnaissance

1. Visit the **Exploit-DB GHDB** page: [https://www.exploit-db.com/google-hacking-database](https://www.exploit-db.com/google-hacking-database).
2. Identify relevant **Google Dorks** based on your target.
3. Use search operators in Google (or alternative search engines like **Bing** or **DuckDuckGo**).
4. Analyze the search results and document findings.

---

## Tools to Automate GHDB Queries

- **Googler**: A command-line tool to perform Google searches.  
- **GooDork**: A Python-based tool to automate Google Dorking.  
- **SearchSploit**: Allows local querying of GHDB.  
- **GHunt**: Tool for analyzing Google accounts.  

---

## Ethical Usage

- Google Hacking and GHDB queries are **powerful tools**.  
- Use them only for **authorized penetration testing** or **ethical hacking** purposes.  
- **Unauthorized use** can lead to legal consequences.

---

## Conclusion

The **Google Hacking Database (GHDB)** is an essential resource for ethical hackers to perform **advanced reconnaissance** and uncover exposed sensitive information during the **footprinting phase**.

- **Resource Link**: [GHDB on Exploit-DB](https://www.exploit-db.com/google-hacking-database)

<br><br>
# Advanced Google Dorking Techniques and Queries

## 1. **Basic Operators**

| **Operator** | **Purpose**                              | **Example**                               |
|--------------|------------------------------------------|------------------------------------------|
| `site:`      | Limits search results to a domain        | `site:example.com`                       |
| `filetype:`  | Finds specific file types                | `filetype:pdf site:example.com`          |
| `intitle:`   | Searches for words in the title          | `intitle:"admin login"`                  |
| `inurl:`     | Searches for words in the URL            | `inurl:wp-admin`                         |
| `intext:`    | Searches for specific text in the page   | `intext:"password"`                      |
| `cache:`     | Shows cached version of a webpage        | `cache:example.com`                      |
| `related:`   | Finds sites related to a given site      | `related:example.com`                    |
| `link:`      | Finds pages linking to a URL (deprecated)| `link:example.com`                       |

---

## 2. **Files and Sensitive Information**

| **Purpose**                           | **Google Dork Query**                           |
|---------------------------------------|-----------------------------------------------|
| Search for text files with passwords  | `filetype:txt intext:password`                |
| Find log files                        | `filetype:log intext:password`                |
| Locate configuration files            | `filetype:conf intext:password`               |
| Search for SQL database dumps         | `filetype:sql intext:password`                |
| Search for environment variables      | `filetype:env inurl:.env`                     |
| Exposed Excel spreadsheets            | `filetype:xls intext:password`                |
| Access Apache server configuration    | `filetype:conf "server config"`               |
| Find backup files                     | `filetype:bak site:example.com`               |
| Discover PDF documents                | `filetype:pdf site:example.com`               |
| Exposed emails in text files          | `filetype:txt intext:@gmail.com`              |
| Exposed JSON files                    | `filetype:json site:example.com`              |
| Search for robots.txt files           | `inurl:robots.txt`                            |

---

## 3. **Login and Admin Pages**

| **Purpose**                           | **Google Dork Query**                          |
|---------------------------------------|-----------------------------------------------|
| Find admin login pages                | `inurl:admin`                                 |
| WordPress login pages                 | `inurl:wp-login.php`                          |
| Joomla admin pages                    | `inurl:administrator`                         |
| cPanel login pages                    | `inurl:2082` OR `inurl:2083`                  |
| Webmail login portals                 | `inurl:webmail`                               |
| phpMyAdmin login pages                | `inurl:phpmyadmin`                            |
| Remote login portals                  | `intitle:"Remote Login"`                      |

---

## 4. **Directory Listings**

| **Purpose**                           | **Google Dork Query**                          |
|---------------------------------------|-----------------------------------------------|
| Find open directories                 | `intitle:"index of" "parent directory"`       |
| Locate directories with movies        | `intitle:"index of" (mp4|avi|mkv)`            |
| Music and MP3 files                   | `intitle:"index of" (mp3|flac|wav)`           |
| Software directories                  | `intitle:"index of" (exe|msi|iso)`            |
| PHP-based directories                 | `intitle:"index of" "php"`                    |

---

## 5. **Error Messages and Debug Information**

| **Purpose**                           | **Google Dork Query**                          |
|---------------------------------------|-----------------------------------------------|
| Expose MySQL errors                   | `intext:"mysql error" site:example.com`       |
| Identify PHP errors                   | `intext:"PHP Parse error" site:example.com`   |
| Debug information                     | `intext:"Fatal error" "on line"`              |
| Configuration details                 | `inurl:phpinfo.php`                           |
| Database error pages                  | `intext:"SQL syntax error"`                   |

---

## 6. **Network and Server Information**

| **Purpose**                           | **Google Dork Query**                          |
|---------------------------------------|-----------------------------------------------|
| Detect server banners                 | `intext:"Apache/2.4.7"`                       |
| Search for FTP servers                | `intitle:"FTP root" site:example.com`         |
| Search for Telnet services            | `intitle:"Telnet Service"`                    |
| Detect IIS servers                    | `inurl:iisadmin`                              |

---

## 7. **Webcams and IoT Devices**

| **Purpose**                           | **Google Dork Query**                          |
|---------------------------------------|-----------------------------------------------|
| Search for open webcams               | `inurl:"view.shtml" "Network Camera"`         |
| Find unsecured CCTV cameras           | `inurl:"top.htm" inurl:"currenttime"`         |
| Search for unsecured printers         | `inurl:hp/device/this.LCDisp`                 |
| Search for open IoT devices           | `inurl:"main.cgi" "Network Device"`           |

---

## 8. **Vulnerable Applications**

| **Purpose**                           | **Google Dork Query**                          |
|---------------------------------------|-----------------------------------------------|
| Search for outdated WordPress sites   | `inurl:wp-content/plugins/`                   |
| Search for outdated Joomla sites      | `inurl:components/com_`                       |
| Find vulnerable PHPMyAdmin versions   | `inurl:phpmyadmin "phpMyAdmin"`               |
| Detect outdated web applications      | `inurl:changelog.txt`                         |
| Identify software with known CVEs     | `intext:"powered by Apache 2.4.7"`            |

---

## 9. **Social Security and Financial Data**

| **Purpose**                           | **Google Dork Query**                          |
|---------------------------------------|-----------------------------------------------|
| Search for exposed credit cards       | `intext:"Visa" "credit card number"`          |
| Expose Social Security numbers        | `intext:"SSN" "XXX-XX-XXXX"`                  |
| Financial reports and files           | `filetype:xls OR filetype:csv "account"`      |

---

## 10. **Automating Google Dorking**

- **Tools**:
  - **GHDB** (Google Hacking Database): [https://www.exploit-db.com/google-hacking-database](https://www.exploit-db.com/google-hacking-database)
  - **Googler**: Command-line tool for Google searches.
  - **GooDork**: Automates Google Dorking queries.
  - **SearchSploit**: Query GHDB locally from the terminal.

---

## 11. **Ethical Usage**

1. **Authorized Testing**: Only use Google Dorks for penetration testing and ethical hacking on authorized systems.
2. **Avoid Misuse**: Unauthorized access or data retrieval is illegal and unethical.
3. **Document Findings**: Record results responsibly and use them for security improvement.

---

## Conclusion

Google Dorking is a **powerful technique** for information gathering and footprinting. The **Google Hacking Database (GHDB)** provides a vast collection of dorks for uncovering sensitive information, vulnerable systems, and misconfigurations.

- **Resource Link**: [GHDB on Exploit-DB](https://www.exploit-db.com/google-hacking-database)

---
<br><br>

# WHOIS Complete Usage Guide

WHOIS is a protocol used to query databases for domain and IP registration details, including ownership, registrar, and administrative information. It is widely used for **cybersecurity**, **domain research**, and **network troubleshooting**.

---

## 1. What is WHOIS?

WHOIS is a **TCP-based query-response protocol** that retrieves domain or IP registration information from central databases maintained by registrars and Regional Internet Registries (RIRs).

---

## 2. Key Information Retrieved Using WHOIS

- **Domain Name**: The domain being queried.
- **Registrar**: The service provider where the domain is registered.
- **Registrant Information**: Contact details (may be private).
- **Name Servers**: DNS servers associated with the domain.
- **Domain Status**: Active, expired, or locked states.
- **Creation Date**: When the domain was registered.
- **Expiration Date**: When the domain will expire.
- **WHOIS Server**: Server providing the WHOIS record.

---

## 3. Why Use WHOIS?

- **Cybersecurity**: Investigate phishing or malicious domains.
- **Domain Research**: Check ownership and availability.
- **Incident Response**: Report abuse or DNS misconfigurations.
- **Penetration Testing**: Collect target information during footprinting.
- **Compliance**: Verify ownership for takedowns or legal actions.

---
## 5. WHOIS Commands for Different Scenarios

| **Purpose**                        | **Command**                                |
|------------------------------------|--------------------------------------------|
| Basic WHOIS Lookup (Domain)        | `whois example.com`                        |
| WHOIS Lookup for an IP Address     | `whois 8.8.8.8`                            |
| Filter Specific Information        | `whois example.com | grep "Registrar"`     |
| Query a Specific WHOIS Server      | `whois -h whois.verisign-grs.com example.com` |
| Save Output to a File              | `whois example.com > output.txt`           |
| Perform WHOIS for Multiple Domains | `for domain in $(cat domains.txt); do whois $domain; done` |

###**dig** | **nslookup** | **host** |   --are some alternatives

