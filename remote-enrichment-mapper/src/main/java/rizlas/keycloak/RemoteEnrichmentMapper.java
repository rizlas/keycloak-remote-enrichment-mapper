package rizlas.keycloak;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperContainerModel;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
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

@AutoService(ProtocolMapper.class)
public class RemoteEnrichmentMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {
    private static final Logger log = LoggerFactory.getLogger(RemoteEnrichmentMapper.class);

    private static final List<String> PROTECTED_CLAIMS = List.of(
            IDToken.NONCE,
            IDToken.AUTH_TIME,
            IDToken.SESSION_STATE,
            IDToken.AT_HASH,
            IDToken.C_HASH,
            IDToken.S_HASH,
            IDToken.NAME,
            IDToken.GIVEN_NAME,
            IDToken.FAMILY_NAME,
            IDToken.MIDDLE_NAME,
            IDToken.NICKNAME,
            IDToken.PREFERRED_USERNAME,
            IDToken.PROFILE,
            IDToken.PICTURE,
            IDToken.WEBSITE,
            IDToken.EMAIL,
            IDToken.EMAIL_VERIFIED,
            IDToken.GENDER,
            IDToken.BIRTHDATE,
            IDToken.ZONEINFO,
            IDToken.LOCALE,
            IDToken.PHONE_NUMBER,
            IDToken.PHONE_NUMBER_VERIFIED,
            IDToken.ADDRESS,
            IDToken.UPDATED_AT,
            IDToken.CLAIMS_LOCALES,
            IDToken.ACR,
            IDToken.SESSION_ID,
            IDToken.AZP,
            IDToken.AUD,
            IDToken.SUBJECT);

    public static final String PROVIDER_ID = "remote-enrichment-token-mapper";
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    private static final String URL_PROPERTY_NAME = "url";
    private static final String URL_AUTH_TOKEN_PROPERTY_NAME = "url_auth_token";
    private static final String URL_AUTH_BASIC_USERNAME_PROPERTY_NAME = "url_auth_username";
    private static final String URL_AUTH_BASIC_PASSWORD_PROPERTY_NAME = "url_auth_password";
    private static final String URL_PARAMS_PROPERTY_NAME = "url_params";
    private static final String URL_PARAMS_SEND_USERNAME = "url_send_username";
    private static final String URL_PARAMS_SEND_CLIENTID = "url_send_clientid";
    private static final String OVERWRITE_EXISTING_CLAIMS = "overwrite_existing_claims";

    static {
        ProviderConfigProperty field;

        // URL
        field = new ProviderConfigProperty();
        field.setName(URL_PROPERTY_NAME);
        field.setLabel("URL");
        field.setHelpText("""
                HTTP(S) URL of the enrichment endpoint that will be called during
                token issuance.
                """);
        field.setType(ProviderConfigProperty.STRING_TYPE);
        field.setRequired(true);
        configProperties.add(field);

        // Username
        field = new ProviderConfigProperty();
        field.setName(URL_PARAMS_SEND_USERNAME);
        field.setLabel("Include username");
        field.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        field.setHelpText("""
                If enabled, the authenticated user's username will be sent
                as a query parameter named 'username'.
                """);
        field.setDefaultValue("true");
        configProperties.add(field);

        // Client ID
        field = new ProviderConfigProperty();
        field.setName(URL_PARAMS_SEND_CLIENTID);
        field.setLabel("Include client ID");
        field.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        field.setHelpText("""
                If enabled, the client identifier will be sent
                as a query parameter named 'client_id'.
                """);
        field.setDefaultValue("true");
        configProperties.add(field);

        // URL Params
        field = new ProviderConfigProperty();
        field.setName(URL_PARAMS_PROPERTY_NAME);
        field.setLabel("GET Params");
        field.setHelpText("""
                Additional query parameters to include in the GET request.
                Use standard URL query syntax, separating parameters with '&'
                (e.g. param_one=value_one&param_two=value_two).

                Dynamic Values:
                - 'user_': Resolves from the User Profile (supported key user_email,
                user_username, user_firstName, user_lastName, user_emailVerified).
                - 'claim_': Resolves from claims already present in the token (e.g. preferred_username).

                Example: param_one=value_one&user_id=user_email&name=claim_name

                Note: some claims may not be available.
                """);
        field.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(field);

        // Authentication Token
        field = new ProviderConfigProperty();
        field.setName(URL_AUTH_TOKEN_PROPERTY_NAME);
        field.setLabel("Authentication Token");
        field.setHelpText("""
                Token used to authenticate requests to the endpoint. Leave empty if it
                does not require authentication. If set, this take precedence over basic
                authentication.
                """);
        field.setType(ProviderConfigProperty.PASSWORD);
        field.setSecret(true);
        configProperties.add(field);

        // Basic authentication username
        field = new ProviderConfigProperty();
        field.setName(URL_AUTH_BASIC_USERNAME_PROPERTY_NAME);
        field.setLabel("Basic authentication username");
        field.setHelpText("The username for Basic Authentication.");
        field.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(field);

        // Basic authentication password
        field = new ProviderConfigProperty();
        field.setName(URL_AUTH_BASIC_PASSWORD_PROPERTY_NAME);
        field.setLabel("Basic authentication password");
        field.setHelpText("The password for Basic Authentication.");
        field.setType(ProviderConfigProperty.PASSWORD);
        field.setSecret(true);
        configProperties.add(field);

        // Claim Mapping Strategy (dummy-field)
        field = new ProviderConfigProperty();
        field.setName("tokenClaimNameInfo");
        field.setLabel("Claim Mapping Strategy");
        field.setHelpText("""
                When Token Claim Name is set, stores the entire authorization
                response in one claim.
                When empty, the mapper emits individual claims.
                """);
        field.setType(ProviderConfigProperty.STRING_TYPE);
        field.setDefaultValue("""
                This is a dummy field. Please click the question mark to know more.
                """);
        configProperties.add(field);

        // Overwrite Existing Claims
        field = new ProviderConfigProperty();
        field.setName(OVERWRITE_EXISTING_CLAIMS);
        field.setLabel("Overwrite existing claims");
        field.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        field.setHelpText("""
                If enabled, the mapper will overwrite claims that already exist in the
                token (except for protected native Keycloak claims).
                If disabled, existing claims will be preserved.
                """);
        field.setDefaultValue("false");
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
                Adds claims to OIDC tokens by enriching user data from an external
                authoritative source.
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
            throw new ProtocolMapperConfigException(
                    "URL is required",
                    URL_PROPERTY_NAME);
        }

        try {
            URI uri = URI.create(url);
            if (!("http".equals(uri.getScheme()) || "https".equals(uri.getScheme()))) {
                throw new IllegalArgumentException();
            }
        } catch (Exception e) {
            throw new ProtocolMapperConfigException(
                    "Invalid URL format (must be HTTP or HTTPS)",
                    URL_PROPERTY_NAME);
        }
    };

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession,
            KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {
        // This will iterate for every token type requested

        Map<String, String> configs = mappingModel.getConfig();
        UserModel user = userSession.getUser();

        String url = configs.get(URL_PROPERTY_NAME);
        String authToken = configs.get(URL_AUTH_TOKEN_PROPERTY_NAME);
        String authBasicUsername = configs.get(URL_AUTH_BASIC_USERNAME_PROPERTY_NAME);
        String authBasicPassword = configs.get(URL_AUTH_BASIC_PASSWORD_PROPERTY_NAME);
        String tokenClaimName = configs.get(OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME);

        boolean sendUsername = Boolean.parseBoolean(configs.get(URL_PARAMS_SEND_USERNAME));
        boolean sendClientId = Boolean.parseBoolean(configs.get(URL_PARAMS_SEND_CLIENTID));

        String rawParams = configs.get(URL_PARAMS_PROPERTY_NAME);

        boolean overwriteExisting = Boolean.parseBoolean(configs.get(OVERWRITE_EXISTING_CLAIMS));

        String username = user.getUsername();
        String clientId = clientSessionCtx.getClientSession().getClient().getClientId();

        Map<String, String> queryParams = new LinkedHashMap<>();

        if (sendUsername)
            queryParams.put("username", username);

        if (sendClientId)
            queryParams.put("client_id", clientId);

        if (rawParams != null && !rawParams.isBlank()) {
            parseParams(token, user, rawParams, queryParams);
        }

        SimpleHttp enrichmentEndpoint = SimpleHttp.doGet(url, keycloakSession)
                .acceptJson()
                .socketTimeOutMillis(2000)
                .connectTimeoutMillis(1000);

        if (authToken != null && !authToken.isBlank()) {
            enrichmentEndpoint.auth(authToken); // Authorization: Bearer <token>
        } else if (authBasicUsername != null && !authBasicUsername.isBlank() &&
                authBasicPassword != null && !authBasicPassword.isBlank()) {
            enrichmentEndpoint.authBasic(authBasicUsername, authBasicPassword);
        }

        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : queryParams.entrySet()) {
            String k = e.getKey();
            String v = e.getValue();
            enrichmentEndpoint.param(k, v);

            if (sb.length() > 0)
                sb.append("&");

            sb.append(k).append("=").append(v);
        }

        String fullUrl = enrichmentEndpoint.getUrl();

        if (!queryParams.isEmpty())
            fullUrl += "?" + sb.toString();

        Map<String, Object> response = callEnrichmentEndpoint(enrichmentEndpoint, fullUrl);

        if (response == null || response.isEmpty()) {
            log.debug("No enrichment data returned, skipping claim mapping");
            return;
        }

        // Token Claim Name is configured → map the entire response into a single claim
        if (tokenClaimName != null && !tokenClaimName.isBlank()) {
            OIDCAttributeMapperHelper.mapClaim(token, mappingModel, response);
        } else {
            // Token Claim Name is NOT configured → add each key from the response as an
            // individual claim
            Map<String, Object> claims = token.getOtherClaims();

            response.forEach((key, value) -> {
                // Check if the claim is in the protected native fields blacklist
                if (PROTECTED_CLAIMS.contains(key)) {
                    log.warn("Blocked attempt to overwrite protected claim: '{}'", key);
                    return;
                }

                // Check if the claim already exists (e.g., added by another mapper)
                // This ensures the remote mapper does not overwrite internal data
                if (claims.containsKey(key) && !overwriteExisting) {
                    log.debug("Claim '{}' already exists in token, skipping remote value", key);
                    return;
                }

                claims.put(key, value);
            });
        }
    }

    private Map<String, Object> callEnrichmentEndpoint(SimpleHttp enrichmentEndpoint, String url) {
        log.debug("Calling enrichment endpoint: {}", url);

        try {
            SimpleHttp.Response response = enrichmentEndpoint.asResponse();

            int status = response.getStatus();
            if (status < 200 || status >= 300) {
                log.warn("Enrichment endpoint returned non-success status {}", status);
                return null;
            }

            return response.asJson(new TypeReference<>() {
            });
        } catch (IOException e) {
            log.error("Error calling enrichment endpoint", e);
            return null;
        }
    }

    private String getClaimValue(IDToken token, String claimName) {
        Object customClaim = token.getOtherClaims().get(claimName);
        return (customClaim != null) ? String.valueOf(customClaim) : null;
    }

    private String getUserAttribute(UserModel user, String attributeName) {
        return switch (attributeName) {
            case "email" -> user.getEmail();
            case "username" -> user.getUsername();
            case "firstName" -> user.getFirstName();
            case "lastName" -> user.getLastName();
            case "emailVerified" -> String.valueOf(user.isEmailVerified());
            default -> null;
        };
    }

    private String resolveParamValue(String value, UserModel user, IDToken token) {
        if (value.startsWith("user_")) {
            String attrName = value.substring("user_".length());
            return getUserAttribute(user, attrName);
        }

        if (value.startsWith("claim_")) {
            String claimName = value.substring("claim_".length());
            return getClaimValue(token, claimName);
        }

        return value;
    }

    private void parseParams(IDToken token, UserModel user, String rawParams, Map<String, String> queryParams) {
        for (String pair : rawParams.split("&")) {

            String[] kv = pair.split("=", 2);
            if (kv.length != 2) {
                log.warn("Skipping invalid query parameter '{}'", pair);
                continue;
            }

            String key = kv[0];
            String value = kv[1];
            String resolvedValue = resolveParamValue(value, user, token);

            if (resolvedValue == null || resolvedValue.isBlank()) {
                log.warn("Resolved value for parameter '{}' was null or empty", key);
                continue;
            }

            queryParams.put(key, resolvedValue);
        }
    }
}
