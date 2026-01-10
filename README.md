# keycloak-remote-enrichment-mapper

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


- https://www.keycloak.org/docs-api/latest/javadocs/org/keycloak/protocol/oidc/mappers/AbstractOIDCProtocolMapper.html
- https://www.baeldung.com/keycloak-custom-protocol-mapper
