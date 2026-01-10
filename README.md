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
