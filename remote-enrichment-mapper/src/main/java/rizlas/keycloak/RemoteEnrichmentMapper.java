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
    private static final String URL_PROPERTY_DEFAULT = "https://postman-echo.com/get";
    private static final String URL_AUTH_TOKEN_PROPERTY_NAME = "url_auth_token";
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
                HTTP(S) URL of the authz enrichment endpoint that will be called during
                token issuance.
                """);
        field.setType(ProviderConfigProperty.STRING_TYPE);
        field.setDefaultValue(URL_PROPERTY_DEFAULT);
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

                You can also reference existing token claims by using the prefix
                'claim_'. The claim value will be resolved at runtime and sent as a
                query parameter. If the claim does not exist in the token, the parameter
                will be omitted from the request.

                Example: param_one=value_one&username=claim_preferred_username

                Allowed claims are: name, given_name, family_name, middle_name,
                nickname, preferred_username, email, birthdate, zoneinfo, locale,
                phone_number, sub.
                """);
        field.setType(ProviderConfigProperty.STRING_TYPE);
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
        String tokenClaimName = configs.get(OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME);

        boolean sendUsername = Boolean.parseBoolean(configs.get(URL_PARAMS_SEND_USERNAME));
        boolean sendClientId = Boolean.parseBoolean(configs.get(URL_PARAMS_SEND_CLIENTID));

        String rawParams = configs.get(URL_PARAMS_PROPERTY_NAME);

        boolean overwriteExisting = Boolean.parseBoolean(configs.get(OVERWRITE_EXISTING_CLAIMS));

        String username = userSession.getUser().getUsername();
        String clientId = clientSessionCtx.getClientSession().getClient().getClientId();

        String debugLogMsg = url;
        List<String> debugLogMsgParams = new ArrayList<>();

        SimpleHttp enrichmentEndpoint = SimpleHttp.doGet(url, keycloakSession)
                .acceptJson()
                .socketTimeOutMillis(2000) // 2 secondi
                .connectTimeoutMillis(1000); // 1 secondo

        if (sendUsername) {
            enrichmentEndpoint.param("username", username);
            debugLogMsgParams.add(String.format("username=%s", username));
        }

        if (sendClientId) {
            enrichmentEndpoint.param("client_id", clientId);
            debugLogMsgParams.add(String.format("client_id=%s", clientId));
        }

        if (rawParams != null && !rawParams.isBlank()) {
            for (String pair : rawParams.split("&")) {
                String[] kv = pair.split("=", 2);
                if (kv.length != 2) {
                    continue;
                }

                String key = kv[0];
                String value = kv[1];

                if (value.startsWith("claim_")) {
                    String claimName = value.substring("claim_".length());
                    log.debug("Request claim '{}' from param", claimName);
                    String claim = getClaimValue(token, claimName);

                    if (claim != null && !claim.isBlank()) {
                        enrichmentEndpoint.param(key, claim);
                        debugLogMsgParams.add(String.format("%s=%s", key, claim));
                    } else {
                        log.warn("Claim {} requested but was null or empty in token", claimName);
                    }
                } else {
                    enrichmentEndpoint.param(key, value);
                    debugLogMsgParams.add(String.format("%s=%s", key, value));
                }
            }
        }

        if (authToken != null && !authToken.isBlank()) {
            enrichmentEndpoint.auth(authToken); // Authorization: Bearer <token>
        }

        if (!debugLogMsgParams.isEmpty()) {
            debugLogMsg += "?" + String.join("&", debugLogMsgParams);
        }

        log.debug("Calling enrichment endpoint: {}", debugLogMsg);

        Map<String, Object> authzResponse;

        try {
            int status = enrichmentEndpoint.asStatus();

            if (status < 200 || status >= 300) {
                String msg = String.format("Authorization endpoint error, status code: %d", status);
                log.error(msg);
                throw new ProtocolMapperConfigException(msg, URL_PROPERTY_NAME);
            }

            authzResponse = enrichmentEndpoint.asJson(new TypeReference<>() {
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

    private String getClaimValue(IDToken token, String claimName) {
        // Check and get from custom claim
        Object customClaim = token.getOtherClaims().get(claimName);
        if (customClaim != null)
            return String.valueOf(customClaim);

        // Check and get from standard claims of IDToken and JsonWebToken
        return switch (claimName) {
            case IDToken.NAME -> token.getName();
            case IDToken.GIVEN_NAME -> token.getGivenName();
            case IDToken.FAMILY_NAME -> token.getFamilyName();
            case IDToken.MIDDLE_NAME -> token.getMiddleName();
            case IDToken.NICKNAME -> token.getNickName();
            case IDToken.PREFERRED_USERNAME -> token.getPreferredUsername();
            case IDToken.EMAIL -> token.getEmail();
            case IDToken.BIRTHDATE -> token.getBirthdate();
            case IDToken.ZONEINFO -> token.getZoneinfo();
            case IDToken.LOCALE -> token.getLocale();
            case IDToken.PHONE_NUMBER -> token.getPhoneNumber();
            case IDToken.SUBJECT -> token.getSubject();
            default -> null;
        };
    }
}
