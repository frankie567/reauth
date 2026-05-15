---
name: openid-connect-discovery
description: "OpenID Connect Discovery 1.0 - Defines mechanism for Relying Party to discover OpenID Provider and obtain OAuth 2.0 endpoint locations. Covers Issuer Discovery, Provider Metadata, and Configuration Information retrieval. Use when working with OpenID Provider discovery, well-known endpoints, or metadata configuration."
---

# OpenID Connect Discovery 1.0

OpenID Connect Discovery 1.0 defines a mechanism for an OpenID Connect Relying Party to discover the End-User's OpenID Provider and obtain information needed to interact with it, including its OAuth 2.0 endpoint locations.

This specification enables automatic discovery of OpenID Provider configuration through WebFinger (RFC 7033) for Issuer Discovery and a well-known JSON document location for Provider Metadata retrieval.

## When to Use This Skill

Use this skill when working with:
- OpenID Provider Issuer Discovery using WebFinger
- Identifier normalization (email, URL, hostname, acct URI syntax)
- OpenID Provider Metadata retrieval and validation
- Well-known endpoint configuration (/.well-known/openid-configuration)
- Dynamic client configuration without hardcoded endpoints
- Multi-tenant applications needing to discover providers
- Security considerations for discovery endpoints

## Key Concepts

### Core Processes
- **OpenID Provider Issuer Discovery**: Mechanism for an RP to discover the OP for an End-User using WebFinger protocol
- **OpenID Provider Metadata**: JSON document containing OAuth 2.0 endpoint locations and other configuration information
- **Configuration Information Retrieval**: Process of obtaining OP metadata from well-known location

### Discovery Methods
- **User Input Identifier Types**: Email address, URL, hostname and port, "acct" URI syntax
- **Normalization Steps**: Steps to normalize user input identifiers before discovery
- **WebFinger Integration**: Use of RFC 7033 for locating the OpenID Provider

### Metadata
- **Provider Configuration Request**: HTTP GET request to well-known endpoint
- **Provider Configuration Response**: JSON response containing metadata
- **Metadata Validation**: Requirements for validating provider metadata

### Well-Known Locations
- `/.well-known/openid-configuration` - Standard path for provider metadata
- WebFinger host-meta file location

## Specification Sections

1. **OpenID Provider Issuer Discovery** - Identifier normalization and WebFinger-based discovery
2. **OpenID Provider Metadata** - JSON structure and required fields for provider metadata
3. **Obtaining OpenID Provider Configuration Information** - Request/response for configuration
4. **String Operations** - String processing utilities
5. **Security Considerations** - TLS requirements, impersonation attacks, and other threats
6. **IANA Considerations** - Well-Known URI and OAuth Authorization Server Metadata registries

## Full Specification Text

See [references/openid-connect-discovery-1_0.txt](references/openid-connect-discovery-1_0.txt) for the complete OpenID Connect Discovery 1.0 specification.
