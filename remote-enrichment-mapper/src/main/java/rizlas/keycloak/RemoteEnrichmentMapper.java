package rizlas.keycloak;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperContainerModel;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.ProtocolMapper;
import org.keycloak.protocol.ProtocolMapperConfigException;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

import com.fasterxml.jackson.core.type.TypeReference;
import com.google.auto.service.AutoService;

@Slf4j
@AutoService(ProtocolMapper.class)
public class RemoteEnrichmentMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    public static final String PROVIDER_ID = "remote-enrichment-token-mapper";
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    private static final String URL_PROPERTY_NAME = "url";
    private static final String URL_PROPERTY_DEFAULT = "https://postman-echo.com/get";
    private static final String URL_AUTH_TOKEN_PROPERTY_NAME = "url_auth_token";
    private static final String URL_AUTH_TOKEN_PROPERTY_DEFAULT = "";

    static {
        ProviderConfigProperty field;

        // URL
        field = new ProviderConfigProperty();
        field.setName(URL_PROPERTY_NAME);
        field.setLabel("URL");
        field.setHelpText("""
                HTTP(S) URL of the authz enrichment endpoint that will be called during
                token issuance.
                """);
        field.setType(ProviderConfigProperty.STRING_TYPE);
        field.setDefaultValue(URL_PROPERTY_DEFAULT);
        field.setRequired(true);
        configProperties.add(field);

        // Authentication Token
        field = new ProviderConfigProperty();
        field.setName(URL_AUTH_TOKEN_PROPERTY_NAME);
        field.setLabel("Authentication Token");
        field.setHelpText("""
                Token used to authenticate requests to the endpoint. Leave empty if it
                does not require authentication.
                """);
        field.setType(ProviderConfigProperty.PASSWORD);
        field.setDefaultValue(URL_AUTH_TOKEN_PROPERTY_DEFAULT);
        field.setSecret(true);
        configProperties.add(field);

        // Claim Mapping Strategy (dummy-field)
        field = new ProviderConfigProperty();
        field.setName("tokenClaimNameInfo");
        field.setLabel("Claim Mapping Strategy");
        field.setHelpText("""
                When Token Claim Name is set, stores the entire authorization
                response in one claim.
                When empty, the mapper emits individual claims such as
                quota, groups, etc.
                """);
        field.setType(ProviderConfigProperty.STRING_TYPE);
        field.setDefaultValue(null);
        configProperties.add(field);

        OIDCAttributeMapperHelper.addTokenClaimNameConfig(configProperties);
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties,
                RemoteEnrichmentMapper.class);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return "Remote Token Enrichment";
    }

    @Override
    public String getHelpText() {
        return """
                Adds authorization-related claims to OIDC tokens by enriching user data
                from an external authoritative source.
                """;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public void validateConfig(KeycloakSession session, RealmModel realm, ProtocolMapperContainerModel client,
            ProtocolMapperModel mapperModel) throws ProtocolMapperConfigException {
        String url = mapperModel.getConfig().get(URL_PROPERTY_NAME);
        if (url == null || url.isBlank()) {
            String message = "URL is required";
            log.error(message);
            throw new ProtocolMapperConfigException(
                    message,
                    URL_PROPERTY_NAME);
        }

        try {
            URI uri = URI.create(url);
            if (!("http".equals(uri.getScheme()) || "https".equals(uri.getScheme()))) {
                throw new IllegalArgumentException();
            }
        } catch (Exception e) {
            String message = "Invalid URL format (must be HTTP or HTTPS)";
            log.error(message);
            throw new ProtocolMapperConfigException(
                    message,
                    URL_PROPERTY_NAME);
        }
    };

    @Override
    @SneakyThrows
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession,
            KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {
        // This will iterate for every token type requested
        Map<String, String> configs = mappingModel.getConfig();
        String url = configs.getOrDefault(URL_PROPERTY_NAME, URL_PROPERTY_DEFAULT);
        String authToken = configs.get(URL_AUTH_TOKEN_PROPERTY_NAME);
        String username = userSession.getUser().getUsername();
        String clientId = clientSessionCtx.getClientSession().getClient().getClientId();
        String tokenClaimName = configs.get(OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME);

        log.debug("Requesting URL: {}?username={}&client_id={}", url, username, clientId);

        SimpleHttp authzEndpoint = SimpleHttp.doGet(url, keycloakSession)
                .param("username", username)
                .param("client_id", clientId)
                .acceptJson()
                .socketTimeOutMillis(15000) // 15 seconds
                .connectTimeoutMillis(10000); // 10 seconds

        if (authToken != null && !authToken.isBlank()) {
            authzEndpoint.auth(authToken); // Authorization: Bearer <token>
        }

        Map<String, Object> authzResponse;

        try {
            int status = authzEndpoint.asStatus();

            if (status < 200 || status >= 300) {
                String msg = String.format("Authorization endpoint error, status code: %d", status);
                log.error(msg);
                throw new ProtocolMapperConfigException(msg, URL_PROPERTY_NAME);
            }

            authzResponse = authzEndpoint.asJson(new TypeReference<>() {
            });
        } catch (IOException e) {
            String msg = String.format("Error calling authorization endpoint %s for user %s", url, username);
            log.error(msg, e);
            throw new ProtocolMapperConfigException(msg, URL_PROPERTY_NAME, e);
        }

        // Token Claim Name is configured → map the entire response into a single claim
        if (tokenClaimName != null && !tokenClaimName.isBlank()) {
            OIDCAttributeMapperHelper.mapClaim(token, mappingModel, authzResponse);
        } else {
            // Token Claim Name is NOT configured → add each key from the response as an
            // individual claim
            Map<String, Object> claims = token.getOtherClaims();
            authzResponse.forEach((key, value) -> {
                claims.put(key, value);
            });
        }
    }
}
