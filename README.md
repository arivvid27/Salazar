# Muninn Web Threat Scanner
> By Videsh Arivazhagan

![Muninn Logo](static/images/logo.png)

## Summary

Muninn is an advanced, open-source web security scanner built with Flask and powered by AI. It's designed to help developers and security professionals identify Cross-Site Scripting (XSS) and Cross-Site Request Forgery (CSRF) vulnerabilities in web applications. Using Google's Gemini AI, Muninn provides intelligent analysis of potential security threats, reducing false positives and offering actionable remediation advice.

## Mission Statement

Our mission is to democratize web security by providing accessible, AI-powered tools that help developers identify and fix vulnerabilities before they can be exploited. We believe that security should be integrated into every stage of development, and Muninn aims to make this process more efficient and effective.

## Research

### Cross-Site Scripting (XSS)

Cross-Site Scripting (XSS) remains one of the most prevalent web security vulnerabilities, consistently appearing in the OWASP Top 10. Our research shows that despite its long history, XSS continues to affect modern web applications due to several factors:

#### Types of XSS Vulnerabilities

1. **Reflected XSS**: When user input is immediately returned and displayed without proper sanitization, allowing attackers to craft malicious links that execute when clicked by victims.

2. **Stored XSS**: Occurs when malicious scripts are permanently stored on target servers (in databases, comment fields, etc.) and are later retrieved and displayed to other users.

3. **DOM-based XSS**: Takes place entirely in the browser when client-side JavaScript modifies the DOM in an unsafe way using untrusted data.

#### Impact Analysis

Our investigation into XSS vulnerabilities revealed severe potential impacts:

- **Session hijacking**: Attackers can steal cookies and session tokens, enabling them to impersonate legitimate users.
- **Credential theft**: Through convincing phishing forms injected directly into trusted websites.
- **Data exfiltration**: Sensitive page content can be sent to attacker-controlled servers.
- **Website defacement**: Modifying the appearance of websites, potentially harming brand reputation.
- **Malware distribution**: Using trusted sites to deliver malware to users.

#### Detection Challenges

Modern XSS attacks often bypass traditional detection methods by:
- Using obfuscated JavaScript to evade pattern matching
- Exploiting context-specific encoding vulnerabilities
- Leveraging modern frameworks' dynamic rendering features
- Utilizing browser quirks and inconsistencies

This is why Muninn incorporates AI analysis to provide more nuanced detection capabilities beyond rule-based scanning.

### Cross-Site Request Forgery (CSRF)

CSRF vulnerabilities exploit the trust that websites place in a user's browser, forcing authenticated users to execute unwanted actions.

#### CSRF Attack Vectors

1. **Form submission**: Tricking users into submitting forms to a target site without their knowledge.
2. **State-changing GET requests**: Exploiting non-idempotent GET requests that change server state.
3. **Cross-domain resource loading**: Using HTML tags like img, script, or iframe to trigger authenticated requests.

#### Protection Mechanisms

Our research identified several protection mechanisms that Muninn scans for:

- **CSRF tokens**: Unique, unpredictable values included in forms and verified by the server.
- **SameSite cookies**: Restricting cookie transmission to only same-site contexts.
- **Custom request headers**: Using headers that cannot be set by cross-origin requests.
- **Double submit cookies**: Including the same value in both a cookie and request parameter.

#### Real-world Impact

CSRF vulnerabilities have led to significant security incidents:
- Account takeovers through password or email changes
- Unauthorized financial transactions
- Data manipulation or deletion
- Privilege escalation when combined with other vulnerabilities

Muninn's CSRF scanner evaluates the implementation of protection mechanisms and provides recommendations based on the sensitivity of the detected forms.

## Features

- **Web Crawling**: Automatically discovers pages within the target domain for comprehensive scanning
- **XSS Detection**: Identifies potential Cross-Site Scripting vulnerabilities using pattern recognition and AI analysis
- **CSRF Scanner**: Detects missing or improperly implemented CSRF protections in forms and endpoints
- **AI-Powered Analysis**: Uses Google Gemini AI to verify findings and reduce false positives
- **Detailed Reports**: Provides comprehensive vulnerability reports with severity rankings and remediation guidance
- **Educational Resources**: Includes contextual information about each vulnerability type to help users understand the risks

## Orkes Conductor Integration

### Workflow Orchestration for Threat Analysis

Muninn's architecture supports integration with Orkes Conductor for enhanced workflow orchestration of AI-powered security analysis. This integration replaces direct API calls to Google Gemini with a more scalable, observable, and fault-tolerant workflow approach.

### Why Orkes Conductor?

- **Decoupled Architecture**: Separates scanning logic from AI analysis processes
- **Improved Reliability**: Built-in retry mechanisms, timeouts, and error handling
- **Enhanced Observability**: Monitor and track each step of the vulnerability analysis process
- **Scalability**: Handle multiple concurrent scans without overwhelming the AI service
- **Workflow Versioning**: Maintain and deploy different analysis workflows with versioning

### Architecture Overview

```
┌─────────────┐    ┌────────────────────┐    ┌───────────────────┐
│ Muninn Web  │    │ Orkes Conductor    │    │   AI Analysis     │
│   Scanner   │───►│ Workflow Engine    │───►│ Workers (Gemini)  │
└─────────────┘    └────────────────────┘    └───────────────────┘
       │                     │                        │
       │                     │                        │
       ▼                     ▼                        ▼
┌─────────────┐    ┌────────────────────┐    ┌───────────────────┐
│ Scan Data   │    │ Workflow Execution │    │ Analysis Results  │
│ Repository  │    │ Records & Metrics  │    │ & Recommendations │
└─────────────┘    └────────────────────┘    └───────────────────┘
```

### Implementation Approach

1. **Define Workflow Tasks**:
   - `extractPageFeatures`: Extract security-relevant features from page content
   - `analyzeXSSVulnerabilities`: Analyze potential XSS vulnerabilities
   - `analyzeCSRFVulnerabilities`: Analyze potential CSRF vulnerabilities
   - `aggregateResults`: Combine results and generate final security report

2. **Integration Steps**:
   - Replace direct Gemini API calls in `xss_scanner.py` and `csrf_scanner.py` with Orkes task workers
   - Implement task workers that communicate with the Gemini API
   - Configure workflow definitions in the Orkes Conductor UI or via API
   - Update the scan execution process to trigger and monitor workflows

### Benefits for Security Analysis

- **Consistent Analysis**: Standardized workflows ensure consistent security analysis across scans
- **Analysis Isolation**: Separate AI analysis concerns from core scanning logic
- **Decision Tracking**: Comprehensive audit trail of security decisions and AI reasoning
- **Advanced Patterns**: Support for advanced patterns like dynamic sub-workflows based on initial findings
- **Horizontal Scaling**: Easily scale analysis capacity by adding more workers without code changes

### Future Extensions

- Implement different AI analysis strategies as selectable workflows
- Add specialized workflows for different vulnerability types
- Integrate multiple AI models for consensus-based vulnerability verification
- Implement custom decision workers that combine rule-based and AI-based approaches

## How We Are Unique

Unlike traditional security scanners, Muninn leverages AI to provide more intelligent vulnerability analysis:

1. **Reduced False Positives**: The AI verification step helps eliminate common false positives that plague many security scanners.

2. **Context-Aware Analysis**: Muninn considers the full context of the page, including HTML structure, JavaScript usage, and HTTP headers.

3. **Educational Approach**: Beyond just identifying vulnerabilities, Muninn explains the issues and provides clear remediation guidance.

4. **Open Source and Extensible**: Built with transparency in mind, allowing security professionals to review and extend its capabilities.

5. **Modern Technology Stack**: Utilizes state-of-the-art AI models and web technologies to stay current with evolving threats.

## Steps to Use

### Prerequisites

- Python 3.8+
- Google Gemini API key

### Installation

1. Clone the repository:
   ```
   git clone https://github.com/your-username/muninn.git
   cd muninn
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Create a `.env` file in the project root with your API key:
   ```
   SECRET_KEY=your-secret-key
   GEMINI_API_KEY=your-gemini-api-key
   ```

### Running the Scanner

1. Start the application:
   ```
   python app.py
   ```

2. Open your browser and navigate to `http://localhost:5000`

3. Enter the URL you want to scan in the form and click "Scan"

4. Wait for the scan to complete - you'll be automatically redirected to the results page

### Interpreting Results

The results page provides:
- Overall risk assessment
- Detailed list of vulnerabilities found
- AI analysis explaining the significance of each finding
- Remediation recommendations for each vulnerability

## Troubleshooting

If you encounter any issues or have questions about the project, please contact:

- Videsh Arivazhagan: videshcyber@gmail.com
- Srikar Sampangi: srikarsampangi1243@gmail.com

### Common Issues

1. **Installation problems**: Make sure you're using Python 3.8+ and have all dependencies installed correctly.

2. **API key errors**: Verify your Gemini API key is correctly set in the `.env` file.

3. **Scanning timeouts**: For large websites, the scanner might time out. Consider adjusting the `SCAN_TIMEOUT` value in `config.py`.

4. **False positives**: While we strive to minimize false positives, they can still occur. Review the AI analysis for context before taking action.

## Limitations and Future Improvements

### Current Limitations

- Limited to XSS and CSRF vulnerability detection
- No authentication support for scanning protected pages
- Network and speed constraints when scanning large websites
- Dependence on external API for AI analysis

### Planned Improvements

- Support for authenticated scanning sessions
- Addition of SQL injection and other vulnerability types
- Improved performance for large-scale scans
- Offline AI analysis options for enhanced privacy
- Integration with CI/CD pipelines for automated security testing

## Team

Taumatawhakatangihangakoauauotamateaturipukakapikimaungahoronukupokaiwhenuakitanatahu

## Credits

Muninn is built using the following open-source libraries:

- [Flask](https://flask.palletsprojects.com/): Web framework for the application interface
- [Beautiful Soup](https://www.crummy.com/software/BeautifulSoup/): HTML parsing for vulnerability scanning
- [Requests](https://requests.readthedocs.io/): HTTP library for web crawling
- [Google Generative AI](https://ai.google.dev/): AI-powered analysis of potential vulnerabilities
- [python-dotenv](https://github.com/theskumar/python-dotenv): Environment variable management
- [validators](https://github.com/kvesteri/validators): Input validation utilities

Special thanks to the open-source security community for their research and contributions to web security practices.

---

© 2025 Muninn - Open Source Web Threat Detection. Licensed under MIT.


### First Place Winner for Crack the Code 2025: Safe Surf!
