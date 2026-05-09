---
name: authentication-terminology
description: Provides clear definitions of core authentication and security terms such as identity, principal, subject, authentication, authorization, and common attack vectors. Use when clarifying terminology in authentication, security, or access control contexts.
---

# Authentication and Security Terminology

## Core Concepts

- **Identity**
  The set of attributes (e.g., username, email, unique ID) that define a digital entity (user, device, service). It is what is being claimed during authentication. When implementing functions, use "identity" to refer to the attributes of a user or entity (e.g., `get_identity_by_email`).
- **Principal**
  A specific, unique digital entity (user, service, device) that can be authenticated. It is the active participant in an authentication process.
- **Subject**
  A generic term for any entity (user, process, device) whose identity can be authenticated. It is a broader category that includes principals and other entities that may not always be uniquely identifiable. "Subject" is less precise than "identity" in most authentication contexts and is rarely used in function or variable naming.
- **Authentication**
  The process of verifying the claimed identity of a principal or subject.
- **Authorization**
  The process of determining what an authenticated identity is allowed to do, i.e., granting or denying access to resources.

### Clarifications

- **Identity vs. Subject**
  "Identity" refers to the actual attributes (e.g., email, username) of a digital entity. "Subject" is a more abstract, generic term for any entity that can be authenticated. In practice, "identity" is preferred when referring to the attributes of a user or entity, especially in code (e.g., `get_identity_by_email` rather than `get_subject_by_email`).

## Authentication Methods

- **Factor**
  A category of authentication credentials, such as something you know (password), something you have (token, smart card), or something you are (biometric).
- **Multi-Factor Authentication (MFA)**
  Using two or more factors from different categories for authentication.
- **Single Sign-On (SSO)**
  A mechanism that allows a user to log in once and gain access to multiple related but independent software systems without being prompted to log in again.
- **Credentials**
  Information or objects used to verify identity, such as passwords, tokens, certificates, or biometric data.

## Tokens and Protocols

- **Token**
  A piece of data that represents the identity and permissions of a user, often used in token-based authentication (e.g., JWT, OAuth token).
- **Session**
  A temporary and interactive information interchange between two or more communicating devices or between a computer and user.
- **OAuth 2.0**
  An open standard for authorization, commonly used to grant limited access to a user's information on another website without exposing passwords.
- **OpenID Connect (OIDC)**
  A simple identity layer on top of the OAuth 2.0 protocol, enabling clients to verify the identity of an end-user based on authentication performed by an authorization server.
- **SAML**
  Security Assertion Markup Language, an XML-based open standard for exchanging authentication and authorization data between parties, often used for SSO.

## Identity Management

- **Identity Provider (IdP)**
  A system entity that creates, maintains, and manages identity information for principals and provides authentication services to relying applications.
- **Service Provider (SP)**
  An entity that provides services to end users, often relying on an IdP for authentication.
- **Directory Service**
  A shared information infrastructure for locating, managing, and administering networked resources (e.g., LDAP, Active Directory).

## Security Concepts

- **Confidentiality**
  Ensuring that information is accessible only to those authorized to have access.
- **Integrity**
  Ensuring the accuracy and consistency of data over its lifecycle.
- **Availability**
  Ensuring that systems and data are accessible when needed.
- **Non-repudiation**
  Ensuring that a party cannot deny the authenticity of their signature on a document or a message they sent.
- **Threat**
  Any potential danger to information or systems.
- **Vulnerability**
  A weakness that can be exploited by a threat to cause harm.
- **Risk**
  The potential for loss, damage, or destruction of an asset as a result of a threat exploiting a vulnerability.

## Common Attacks

- **Phishing**
  Attempting to obtain sensitive information by pretending to be a trustworthy entity.
- **Brute Force**
  Trying all possible combinations to guess a password or key.
- **Man-in-the-Middle (MitM)**
  Intercepting and possibly altering messages between two parties who believe they are directly communicating with each other.
- **Credential Stuffing**
  Using lists of user name and password pairs to gain unauthorized access to user accounts.
- **Replay Attack**
  Capturing a valid data transmission and fraudulently or maliciously repeating or delaying it.
