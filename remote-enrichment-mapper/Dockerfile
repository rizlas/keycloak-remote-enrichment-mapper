ARG KC_DOCKER_TAG

FROM maven:3.9.12-amazoncorretto-21-debian AS builder

WORKDIR /app

COPY . .

RUN mvn clean install -DskipTests

FROM quay.io/keycloak/keycloak:${KC_DOCKER_TAG}
ARG ENRICHMENT_MAPPER_VERSION

COPY --from=builder \
  /app/target/rizlas.keycloak.remote-enrichment-mapper-${ENRICHMENT_MAPPER_VERSION}.jar \
  /opt/keycloak/providers/

RUN /opt/keycloak/bin/kc.sh build
