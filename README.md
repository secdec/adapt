![adapt-logo](resources/adapt-logo-Expanded.png?raw=true "Adapt-logo")

# Summary
ADAPT is a tool that performs Automated Dynamic Application Penetration Testing for web applications. It is designed to increase accuracy, speed, and confidence in penetration testing efforts. ADAPT automatically tests for multiple industry standard OWASP Top 10 vulnerabilities, and outputs categorized findings based on these potential vulnerabilities. ADAPT also uses the functionality from OWASP ZAP to perform automated active and passive scans, and auto-spidering. Due to the flexible nature of the ADAPT tool, all of theses features and tests can be enabled or disabled from the configuration file. For more information on tests and configuration, please visit the ADAPT [wiki.](https://github.com/secdec/ADAPT/wiki)


# How it Works
ADAPT uses Python to create an automated framework to use industry standard tools, such as OWASP ZAP and Nmap, to perform repeatable, well-designed procedures with anticipated results to create an easly understandable report listing vulnerabilities detected within the web application.

## Automated Tests:
    * OTG-IDENT-004 – Account Enumeration
    * OTG-AUTHN-001 - Testing for Credentials Transported over an Encrypted Channel
    * OTG-AUTHN-002 – Default Credentials
    * OTG-AUTHN-003 - Testing for Weak lock out mechanism
    * OTG-AUTHZ-001 – Directory Traversal
    * OTG-CONFIG-002 - Test Application Platform Configuration
    * OTG-CONFIG-006 – Test HTTP Methods
    * OTG-CRYPST-001 - Testing for Weak SSL/TLS Ciphers, Insufficient Transport Layer Protection
    * OTG-CRYPST-002 - Testing for Padding Oracle
    * OTG-ERR-001 - Testing for Error Code
    * OTG-ERR-002 – Testing for Stack Traces
    * OTG-INFO-002 – Fingerprinting the Webserver
    * OTG-INPVAL-001 - Testing for Reflected Cross site scripting
    * OTG-INPVAL-002 - Testing for Stored Cross site scripting
    * OTG-INPVAL-003 – HTTP Verb Tampering
    * OTG-SESS-001 - Testing for Session Management Schema
    * OTG-SESS-002 – Cookie Attributes

## Installing the Plugin
1. [Detailed install instructions](https://github.com/secdec/adapt/wiki/Installation).

# For Developers & Contributors
ADAPT is an open source software that encourages community collaboration. Collaboration requires cloning the ADAPT repository from https://github.com/secdec/adapt. It is encouraged that a potential contributor clones ADAPT in a UNIX environment. Cloning in a windows environment may disturb the line endings if certain settings are configured such as autocrlf = true. To ensure that this does not occur when working in a Windows based environment locate your global git.config and disable autocrlf. 


## License
Licensed under the [Apache-2.0](https://github.com/secdec/adapt/blob/master/LICENSE) License.


