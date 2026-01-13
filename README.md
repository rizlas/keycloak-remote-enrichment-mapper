# keycloak-remote-enrichment-mapper

![Contributions welcome](https://img.shields.io/badge/Contributions-Welcome-brightgreen.svg)
![GitHub License](https://img.shields.io/github/license/rizlas/keycloak-remote-enrichment-mapper)
![GitHub Release](https://img.shields.io/github/v/release/rizlas/keycloak-remote-enrichment-mapper)
[![Publish package to GitHub Packages](https://github.com/rizlas/keycloak-remote-enrichment-mapper/actions/workflows/releases.yml/badge.svg?event=release)](https://github.com/rizlas/keycloak-remote-enrichment-mapper/actions/workflows/releases.yml)

## Overview

The **Remote Token Enrichment Mapper** is a custom Keycloak Protocol Mapper that allows
you to fetch additional user claims from an external REST API during the token issuance
process. This is particularly useful for integrating with external authorization
systems, legacy databases, or subscription management services (e.g., Nextcloud quotas,
department-specific roles).

## Key Features

* **Dynamic Payload:** Send the `username`, `client_id`, or any existing token claim or
  user attribute as GET parameters to your enrichment endpoint.
* **Secure Authentication:** Supports both **Bearer Token** and **Basic Authentication**
  (Bearer takes precedence).
* **Security Blacklisting:** Automatically prevents the external API from overwriting
  core OIDC claims (e.g., `sub`, `iss`, `aud`, `exp`) to prevent account takeover or
  session hijacking.
* **Conflict Resolution:** Admin-configurable toggle to decide whether to overwrite
  existing custom claims or preserve them.
* **Caching (Experimental):** When enabled, the mapper stores remote enrichment
  responses in the current token request’s session context to reduce repeated calls to
  the external endpoint.

## Configuration

### Endpoint Settings

* **URL**: The HTTP(S) endpoint to call. Must return a JSON object.
* **GET Params**: Custom static key-value pairs. Use the prefix `claim_` or `user_` to
  dynamically inject values from the current token (e.g.,
  `user_id=user_email&name=claim_name`).

> [!NOTE]
> Getting claim is not guaranteed due to mapper execution order

* **Include username**: If enabled, the authenticated user's username is automatically
  appended as a username query parameter.
* **Include client id**: If enabled, the client identifier (e.g., account, my-app) is
  automatically appended as a client_id query parameter.
* **Authentication Token**: Used for Bearer authentication. If set, it sends the
  Authorization: Bearer `<token>` header. This takes precedence over Basic Auth.
* **Basic Auth**: Standard username and password fields. If provided (and no Bearer
  token is set), it sends the Authorization: Basic `<base64>` header.

### Claim Strategy

* **Overwrite existing claims**: If true, the mapper will replace existing claims in the
  token with values from the remote API (excluding protected native claims). If false,
  existing values are preserved.
* **Token Claim Name**:
  * If **provided**: The entire JSON response from the API is nested under this single
    key.

```json
{
  "exp": 1768165403,
  "iat": 1768165343,
  "jti": "8fe566b2-08e0-803b-cad3-3a1e637feeb6",
  "iss": "http://127.0.0.1:8080/realms/master",
  "aud": "account",
  "sub": "fa3fdbf7-4b9a-4e78-8837-a43b895a6d63",
  "typ": "ID",
  "azp": "account",
  "sid": "c5ce6868-dd31-4964-b0d5-8562ba74b2f3",
  "acr": "1",
  "email_verified": false,
  "name": "John Doe",
  "preferred_username": "admin",
  "given_name": "John",
  "custom_claim_name": {
    "args": {
      "user_id": "admin@keycloak.org",
      "name": "John Doe",
      "client_id": "account",
      "username": "admin",
      "param_one": "value_one"
    },
    "headers": {
      "host": "postman-echo.com",
      "accept-encoding": "gzip, br",
      "user-agent": "Apache-HttpClient/4.5.14 (Java/21.0.8)",
      "x-forwarded-proto": "https",
      "accept": "application/json"
    },
    "url": "https://postman-echo.com/get?user_id=admin%40keycloak.org&name=John+Doe&client_id=account&username=admin&param_one=value_one"
  },
  "family_name": "Doe",
  "email": "admin@keycloak.org"
}
```

  * If **empty**: The JSON response is flattened, and each key is added as a top-level
    claim.

```json
{
  "exp": 1768165155,
  "iat": 1768165096,
  "jti": "8f0dd94b-5352-1186-a0c5-d2f2f32c0255",
  "iss": "http://127.0.0.1:8080/realms/master",
  "aud": "account",
  "sub": "fa3fdbf7-4b9a-4e78-8837-a43b895a6d63",
  "typ": "ID",
  "azp": "account",
  "sid": "0b78043b-079f-437c-9c18-2c1cf8f8dd90",
  "acr": "1",
  "args": {
    "user_id": "admin@keycloak.org",
    "name": "John Doe",
    "client_id": "account",
    "username": "admin",
    "param_one": "value_one"
  },
  "headers": {
    "host": "postman-echo.com",
    "accept-encoding": "gzip, br",
    "user-agent": "Apache-HttpClient/4.5.14 (Java/21.0.8)",
    "x-forwarded-proto": "https",
    "accept": "application/json"
  },
  "email_verified": false,
  "name": "John Doe",
  "preferred_username": "admin",
  "given_name": "John",
  "family_name": "Doe",
  "url": "https://postman-echo.com/get?user_id=admin%40keycloak.org&name=John+Doe&client_id=account&username=admin&param_one=value_one",
  "email": "admin@keycloak.org"
}
```

## Keycloak version

The mapper is built and tested using the latest Keycloak version available at
development time.

This does **not** prevent it from working with earlier versions of the same major
release (for example `26.1.x` or other `26.x` versions).

Each mapper release specifies the **minimum supported Keycloak version**, starting from
the version used at the beginning of development.

## Develop

Adjust the docker-compose.yml provided and run it

```bash
docker compose up -d --build --force-recreate
```

Open keycloak in your browser <http://127.0.0.1:8080>

A devcontainer is also provided to be used in vscode.

### Testing with Postman Echo

Use `https://postman-echo.com/get` as endpoint for testing. This is an excellent tool
for development because it mirrors back the parameters and headers Keycloak sends,
allowing you to see exactly how the mapper behaves before you build your own API.

## Useful commands

```bash
# Generate folder structure (first bootstrap)
mvn archetype:generate \
  -DgroupId=rizlas.keycloak \
  -DartifactId=remote-enrichment-mapper \
  -DarchetypeArtifactId=maven-archetype-quickstart \
  -DinteractiveMode=false

# Create Jar
mvn clean install -DskipTests

# Resolve dependecies
mvn dependency:resolve
```

## Resources

* <https://www.baeldung.com/keycloak-custom-protocol-mapper>
* <http://www.youtube.com/watch?v=5WBb176YqKg>
* <https://www.keycloak.org/docs-api/latest/javadocs/org/keycloak/protocol/oidc/mappers/AbstractOIDCProtocolMapper.html>
* <https://www.keycloak.org/docs-api/latest/javadocs/org/keycloak/broker/provider/util/SimpleHttp.html>
* <https://github.com/groupe-sii/keycloak-json-remote-claim/tree/master>
* <https://github.com/dasniko/keycloak-extensions-demo/blob/main/tokenmapper/src/main/java/dasniko/keycloak/tokenmapper/EchoMapper.java>

---

Feel free to make pull requests, fork, destroy or whatever you like most. Any criticism
is more than welcome.

<br/>

<div align="center"><img src="https://avatars1.githubusercontent.com/u/8522635?s=96&v=4"/></div>
<p align="center">#followtheturtle</p>
