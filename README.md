# keycloak-remote-enrichment-mapper

## ⚠️ Work In Progress (WIP)

*This project is currently under active development. While the core security features
and authentication logic are implemented, it should be thoroughly tested in a staging
environment before being used in production.*

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

## Configuration

### Endpoint Settings

* **URL**: The HTTP(S) endpoint to call. Must return a JSON object.
* **GET Params**: Custom static key-value pairs. Use the prefix `claim_` or `user_` to
  dynamically inject values from the current token (e.g.,
  `user_id=user_email&name=claim_name`).
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
  * If **empty**: The JSON response is flattened, and each key is added as a top-level
    claim.

## Develop

Adjust the docker-compose.yml provided and run it

```bash
docker compose up -d --build --force-recreate
```

Open keycloak in your browser <http://127.0.0.1:8080>

### Testing with Postman Echo

Use `https://postman-echo.com/get` as endpoint for testing. This is an excellent tool
for development because it mirrors back the parameters and headers Keycloak sends,
allowing you to see exactly how the mapper behaves before you build your own API.

## Generate folder structure (first bootstrap)

```bash
mvn archetype:generate \
  -DgroupId=rizlas.keycloak \
  -DartifactId=remote-enrichment-mapper \
  -DarchetypeArtifactId=maven-archetype-quickstart \
  -DinteractiveMode=false
```

## Create Jar

```bash
mvn clean install -DskipTests
```

## Resources

* <https://www.baeldung.com/keycloak-custom-protocol-mapper>
* <http://www.youtube.com/watch?v=5WBb176YqKg>
* <https://www.keycloak.org/docs-api/latest/javadocs/org/keycloak/protocol/oidc/mappers/AbstractOIDCProtocolMapper.html>
* <https://www.keycloak.org/docs-api/latest/javadocs/org/keycloak/broker/provider/util/SimpleHttp.html>
* <https://github.com/groupe-sii/keycloak-json-remote-claim/tree/master>
* <https://github.com/dasniko/keycloak-extensions-demo/blob/main/tokenmapper/src/main/java/dasniko/keycloak/tokenmapper/EchoMapper.java>
