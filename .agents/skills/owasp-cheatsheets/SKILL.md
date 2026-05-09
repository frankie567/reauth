---
name: owasp-cheatsheets
description: Comprehensive OWASP Cheat Sheet Series skill providing direct access to all OWASP cheat sheets for web application security, secure coding practices, and vulnerability prevention. Use when working on authentication, authorization, injection prevention, cryptography, or any OWASP-related security guidance.
license: CC-BY-SA-4.0
metadata:
  author: OWASP
  version: "1.0"
  source: https://github.com/OWASP/CheatSheetSeries
  categories: "authentication, authorization, injection, xss, csrf, cryptography, security, owasp"
compatibility: Works with any agent or LLM. No special tools required. Requires internet access to fetch remote cheat sheets.
---

# OWASP Cheat Sheet Series

This skill provides direct access to the **OWASP Cheat Sheet Series**, a collection of concise, actionable security guidance for developers, architects, and security professionals. All content is fetched from the official OWASP repository.

## When to Use This Skill

Use this skill when:
- Developing secure web applications
- Reviewing code for security vulnerabilities
- Implementing authentication and authorization systems
- Preventing injection attacks (SQL, XSS, CSRF, etc.)
- Securing data storage and transmission
- Configuring secure infrastructure
- Working with emerging technologies (AI, cloud, containers, etc.)
- Following OWASP best practices

## Quick Start

### Most Common Security Tasks

| Task | Cheat Sheet |
|------|-------------|
| Secure authentication implementation | [Authentication Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Authentication_Cheat_Sheet.md) |
| Password storage best practices | [Password Storage Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Password_Storage_Cheat_Sheet.md) |
| Session management security | [Session Management Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Session_Management_Cheat_Sheet.md) |
| SQL injection prevention | [SQL Injection Prevention Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.md) |
| Cross-site scripting (XSS) prevention | [XSS Prevention Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.md) |
| CSRF prevention | [CSRF Prevention Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md) |
| Input validation | [Input Validation Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Input_Validation_Cheat_Sheet.md) |
| Cryptographic storage | [Cryptographic Storage Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Cryptographic_Storage_Cheat_Sheet.md) |

## Category Overview

The OWASP Cheat Sheet Series is organized into the following categories:

### 1. Authentication & Authorization
All aspects of user identity verification, access control, and session management.

**Cheat Sheets:**
- [Authentication Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Authentication_Cheat_Sheet.md)
- [Password Storage Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Password_Storage_Cheat_Sheet.md)
- [Session Management Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Session_Management_Cheat_Sheet.md)
- [Authorization Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Authorization_Cheat_Sheet.md)
- [Access Control Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Access_Control_Cheat_Sheet.md)
- [Forgot Password Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Forgot_Password_Cheat_Sheet.md)
- [Multifactor Authentication Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Multifactor_Authentication_Cheat_Sheet.md)
- [Choosing and Using Security Questions Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Choosing_and_Using_Security_Questions_Cheat_Sheet.md)
- [Credential Stuffing Prevention Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.md)
- [JAAS Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/JAAS_Cheat_Sheet.md)

### 2. Injection Prevention
Preventing all forms of injection attacks across different technologies.

**Cheat Sheets:**
- [SQL Injection Prevention Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.md)
- [Cross-Site Scripting (XSS) Prevention Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.md)
- [DOM-based XSS Prevention Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.md)
- [XSS Filter Evasion Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.md)
- [Cross-Site Request Forgery (CSRF) Prevention Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md)
- [OS Command Injection Defense Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.md)
- [LDAP Injection Prevention Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.md)
- [Deserialization Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Deserialization_Cheat_Sheet.md)
- [Server Side Request Forgery Prevention Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md)
- [Prototype Pollution Prevention Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.md)
- [Mass Assignment Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Mass_Assignment_Cheat_Sheet.md)
- [Insecure Direct Object Reference Prevention Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.md)
- [Query Parameterization Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Query_Parameterization_Cheat_Sheet.md)
- [Injection Prevention in Java Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Injection_Prevention_in_Java_Cheat_Sheet.md)

### 3. Data Protection
Securing data at rest, in transit, and during processing.

**Cheat Sheets:**
- [Cryptographic Storage Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Cryptographic_Storage_Cheat_Sheet.md)
- [Key Management Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Key_Management_Cheat_Sheet.md)
- [Secrets Management Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Secrets_Management_Cheat_Sheet.md)
- [TLS Cipher String Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/TLS_Cipher_String_Cheat_Sheet.md)
- [HTTP Strict Transport Security Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.md)
- [HTTP Headers Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/HTTP_Headers_Cheat_Sheet.md)
- [Content Security Policy Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Content_Security_Policy_Cheat_Sheet.md)
- [Cookie Theft Mitigation Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Cookie_Theft_Mitigation_Cheat_Sheet.md)
- [Pinning Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Pinning_Cheat_Sheet.md)

### 4. Application Security
General application security principles and practices.

**Cheat Sheets:**
- [Input Validation Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Input_Validation_Cheat_Sheet.md)
- [Error Handling Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Error_Handling_Cheat_Sheet.md)
- [Logging Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Logging_Cheat_Sheet.md)
- [Logging Vocabulary Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Logging_Vocabulary_Cheat_Sheet.md)
- [Secure Code Review Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Secure_Code_Review_Cheat_Sheet.md)
- [Secure Product Design Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Secure_Product_Design_Cheat_Sheet.md)
- [Business Logic Security Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Business_Logic_Security_Cheat_Sheet.md)
- [Attack Surface Analysis Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.md)
- [Abuse Case Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Abuse_Case_Cheat_Sheet.md)
- [Denial of Service Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Denial_of_Service_Cheat_Sheet.md)
- [File Upload Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/File_Upload_Cheat_Sheet.md)
- [Email Validation and Verification Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Email_Validation_and_Verification_Cheat_Sheet.md)
- [Security Terminology Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Security_Terminology_Cheat_Sheet.md)
- [Bean Validation Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Bean_Validation_Cheat_Sheet.md)

### 5. Infrastructure & Deployment Security
Securing the infrastructure and deployment pipeline.

**Cheat Sheets:**
- [Docker Security Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Docker_Security_Cheat_Sheet.md)
- [Kubernetes Security Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Kubernetes_Security_Cheat_Sheet.md)
- [CI/CD Security Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/CI_CD_Security_Cheat_Sheet.md)
- [GitHub Actions Security Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/GitHub_Actions_Security_Cheat_Sheet.md)
- [Infrastructure as Code Security Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.md)
- [Serverless FaaS Security Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Serverless_FaaS_Security_Cheat_Sheet.md)
- [Secure Cloud Architecture Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Secure_Cloud_Architecture_Cheat_Sheet.md)
- [Network Segmentation Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Network_Segmentation_Cheat_Sheet.md)
- [Dependency Graph SBOM Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Dependency_Graph_SBOM_Cheat_Sheet.md)
- [Software Supply Chain Security Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.md)
- [Database Security Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Database_Security_Cheat_Sheet.md)
- [NoSQL Security Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/NoSQL_Security_Cheat_Sheet.md)

### 6. Framework & Language-Specific
Security guidance for specific frameworks and languages.

**Cheat Sheets:**
- [Java Security Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Java_Security_Cheat_Sheet.md)
- [DotNet Security Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/DotNet_Security_Cheat_Sheet.md)
- [Nodejs Security Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Nodejs_Security_Cheat_Sheet.md)
- [NodeJS Docker Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/NodeJS_Docker_Cheat_Sheet.md)
- [PHP Configuration Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/PHP_Configuration_Cheat_Sheet.md)
- [Django Security Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Django_Security_Cheat_Sheet.md)
- [Django REST Framework Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Django_REST_Framework_Cheat_Sheet.md)
- [Ruby on Rails Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Ruby_on_Rails_Cheat_Sheet.md)
- [Laravel Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Laravel_Cheat_Sheet.md)
- [Symfony Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Symfony_Cheat_Sheet.md)
- [C-Based Toolchain Hardening Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/C-Based_Toolchain_Hardening_Cheat_Sheet.md)

### 7. Emerging Technologies
Security for modern and emerging technologies.

**Cheat Sheets:**
- [AI Agent Security Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/AI_Agent_Security_Cheat_Sheet.md)
- [LLM Prompt Injection Prevention Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.md)
- [RAG Security Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/RAG_Security_Cheat_Sheet.md)
- [Secure AI Model Ops Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Secure_AI_Model_Ops_Cheat_Sheet.md)
- [Secure Coding with AI Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Secure_Coding_with_AI_Cheat_Sheet.md)
- [MCP Security Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/MCP_Security_Cheat_Sheet.md)
- [Drone Security Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Drone_Security_Cheat_Sheet.md)
- [Automotive Security Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Automotive_Security_Cheat_Sheet.md)
- [Mobile Application Security Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Mobile_Application_Security_Cheat_Sheet.md)
- [Microservices Security Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Microservices_Security_Cheat_Sheet.md)
- [Microservices based Security Arch Doc Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Microservices_based_Security_Arch_Doc_Cheat_Sheet.md)
- [GraphQL Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/GraphQL_Cheat_Sheet.md)
- [REST Security Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/REST_Security_Cheat_Sheet.md)
- [REST Assessment Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/REST_Assessment_Cheat_Sheet.md)

### 8. Specialized Topics
Niche but important security areas.

**Cheat Sheets:**
- [Browser Extension Vulnerabilities Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Browser_Extension_Vulnerabilities_Cheat_Sheet.md)
- [Third Party Javascript Management Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.md)
- [Securing Cascading Style Sheets Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Securing_Cascading_Style_Sheets_Cheat_Sheet.md)
- [Clickjacking Defense Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Clickjacking_Defense_Cheat_Sheet.md)
- [DOM Clobbering Prevention Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.md)
- [Subdomain Takeover Prevention Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.md)
- [OAuth2 Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/OAuth2_Cheat_Sheet.md)
- [SAML Security Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/SAML_Security_Cheat_Sheet.md)
- [JSON Web Token for Java Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.md)
- [Legacy Application Management Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Legacy_Application_Management_Cheat_Sheet.md)
- [Multi Tenant Security Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.md)
- [Bot Management and Anti-Automation Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Bot_Management_and_Anti-Automation_Cheat_Sheet.md)
- [Authorization Testing Automation Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Authorization_Testing_Automation_Cheat_Sheet.md)

## How to Use This Skill

### For Developers

1. **Identify the security concern** (e.g., "I need to prevent SQL injection")
2. **Navigate to the relevant category** (Injection Prevention)
3. **Click the specific cheat sheet link** (SQL Injection Prevention)
4. **Follow the actionable guidance** provided in the official OWASP documentation

### For Security Reviewers

1. **Use the Attack Surface Analysis Cheat Sheet** to identify potential vulnerabilities
2. **Cross-reference with relevant prevention cheat sheets**
3. **Apply the Secure Code Review Cheat Sheet** principles
4. **Document findings using the Logging Cheat Sheet** guidance

### For Architects

1. **Start with Secure Product Design Cheat Sheet**
2. **Apply Secure Cloud Architecture principles**
3. **Use Microservices Security Cheat Sheet** for distributed systems
4. **Implement Infrastructure as Code Security** best practices

## Common Security Patterns

### Authentication Flow
```
1. User provides credentials (username/password)
2. Validate input (Input Validation Cheat Sheet)
3. Verify password securely (Password Storage Cheat Sheet)
4. Create session (Session Management Cheat Sheet)
5. Set secure cookies (Cookie Theft Mitigation Cheat Sheet)
6. Implement MFA if required (Multifactor Authentication Cheat Sheet)
```

### Secure Data Access
```
1. Receive user input
2. Validate all input (Input Validation Cheat Sheet)
3. Use parameterized queries (SQL Injection Prevention Cheat Sheet)
4. Encode output (XSS Prevention Cheat Sheet)
5. Log access appropriately (Logging Cheat Sheet)
```

### API Security Checklist
- [ ] Input validation on all endpoints (Input Validation)
- [ ] Authentication and authorization (Authentication, Authorization)
- [ ] Rate limiting (Denial of Service)
- [ ] Secure headers (HTTP Headers)
- [ ] CORS configuration
- [ ] Error handling without information leakage (Error Handling)

## OWASP Top 10 Mapping

The cheat sheets align with the OWASP Top 10 vulnerabilities:

| OWASP Top 10 | Relevant Cheat Sheets |
|--------------|------------------------|
| A01:2021 - Broken Access Control | [Access Control](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Access_Control_Cheat_Sheet.md), [Authorization](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Authorization_Cheat_Sheet.md), [Insecure Direct Object Reference Prevention](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.md) |
| A02:2021 - Cryptographic Failures | [Cryptographic Storage](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Cryptographic_Storage_Cheat_Sheet.md), [Password Storage](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Password_Storage_Cheat_Sheet.md), [TLS Cipher String](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/TLS_Cipher_String_Cheat_Sheet.md) |
| A03:2021 - Injection | [SQL Injection Prevention](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.md), [XSS Prevention](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.md), [OS Command Injection](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.md), [LDAP Injection](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.md), [Deserialization](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Deserialization_Cheat_Sheet.md) |
| A04:2021 - Insecure Design | [Secure Product Design](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Secure_Product_Design_Cheat_Sheet.md), [Business Logic Security](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Business_Logic_Security_Cheat_Sheet.md), [Attack Surface Analysis](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.md) |
| A05:2021 - Security Misconfiguration | [HTTP Headers](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/HTTP_Headers_Cheat_Sheet.md), [Content Security Policy](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Content_Security_Policy_Cheat_Sheet.md), [Secure Cloud Architecture](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Secure_Cloud_Architecture_Cheat_Sheet.md) |
| A06:2021 - Vulnerable and Outdated Components | [Dependency Graph SBOM](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Dependency_Graph_SBOM_Cheat_Sheet.md), [Software Supply Chain Security](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.md) |
| A07:2021 - Identification and Authentication Failures | [Authentication](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Authentication_Cheat_Sheet.md), [Password Storage](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Password_Storage_Cheat_Sheet.md), [Session Management](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Session_Management_Cheat_Sheet.md), [Multifactor Authentication](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Multifactor_Authentication_Cheat_Sheet.md) |
| A08:2021 - Software and Data Integrity Failures | [Input Validation](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Input_Validation_Cheat_Sheet.md), [File Upload](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/File_Upload_Cheat_Sheet.md), [Deserialization](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Deserialization_Cheat_Sheet.md) |
| A09:2021 - Security Logging and Monitoring Failures | [Logging](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Logging_Cheat_Sheet.md), [Logging Vocabulary](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Logging_Vocabulary_Cheat_Sheet.md) |
| A10:2021 - Server-Side Request Forgery | [SSRF Prevention](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md) |

## Best Practices Summary

### Always Do
- Use parameterized queries for all database access
- Validate all input on the server side
- Encode all output based on context
- Store passwords using strong hashing (bcrypt, Argon2, PBKDF2)
- Use HTTPS for all communications
- Implement proper session management
- Apply the principle of least privilege
- Log security-relevant events

### Never Do
- Use string concatenation for SQL queries
- Store passwords in plaintext or using weak hashing (MD5, SHA1)
- Trust client-side validation alone
- Expose sensitive information in error messages
- Use predictable session IDs
- Disable security headers
- Ignore security in the design phase

## Complete Cheat Sheet Index

For a complete, searchable list of all cheat sheets, visit:
- [OWASP Cheat Sheet Series Repository](https://github.com/OWASP/CheatSheetSeries/tree/master/cheatsheets)
- [OWASP Cheat Sheet Series Website](https://cheatsheetseries.owasp.org/)

## Original Source

All content is sourced from the [OWASP Cheat Sheet Series](https://github.com/OWASP/CheatSheetSeries) repository, licensed under [CC-BY-SA-4.0](https://creativecommons.org/licenses/by-sa/4.0/).

For the most up-to-date information, always refer to the official OWASP repository.
