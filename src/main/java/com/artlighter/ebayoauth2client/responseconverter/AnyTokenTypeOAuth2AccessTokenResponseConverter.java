package com.artlighter.ebayoauth2client.responseconverter;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.util.StringUtils;

import java.util.*;

/**
 * OAuth2AccessTokenResponseConverter that converts third-party API response with auth token to
 * OAuth2AccessTokenResponse even if API responded with token_type other than 'Bearer'.
 *
 * Some APIs respond with proper OAuth2 Tokens that can be used to access their RESTful APIs
 * but specify their type as something different rather than 'Bearer'
 * (for example, eBay responds with 'User Access Token'). Standard OAuth2 Spring Flow doesn't accept OAuth2 tokens
 * if response specifies other token_type.
 * This converter exists to fix this issue and convert unknown token_type to 'Bearer'.
 * It can identify only specified token types as 'Bearer' or every token type if none were specified.
 */
public final class AnyTokenTypeOAuth2AccessTokenResponseConverter
        implements Converter<Map<String, Object>, OAuth2AccessTokenResponse> {

    private final Set<String> TOKEN_RESPONSE_PARAMETER_NAMES =
            new HashSet(Arrays.asList("access_token", "expires_in", "refresh_token", "scope", "token_type"));
    private Set<String> availableTokenTypes;

    /**
     * Constructor
     * @param tokenTypes - Token types that can be interpreted as 'Bearer'
     */
    public AnyTokenTypeOAuth2AccessTokenResponseConverter(String... tokenTypes) {
        availableTokenTypes = new HashSet<>();
        for (String tokenType : tokenTypes) {
            availableTokenTypes.add(tokenType);
        }
    }

    /**
     * Constructor
     * @param availableTokenTypes - Set of token types that can be interpreted as 'Bearer'
     */
    public AnyTokenTypeOAuth2AccessTokenResponseConverter(Set<String> availableTokenTypes) {
        this.availableTokenTypes = availableTokenTypes;
    }

    /**
     * Constructor with no args. Use this if you need to accept every token type as 'Bearer'
     */
    public AnyTokenTypeOAuth2AccessTokenResponseConverter() {

    }

    /**
     * @see org.springframework.security.oauth2.core.endpoint.DefaultMapOAuth2AccessTokenResponseConverter#convert(Map) 
     */
    public OAuth2AccessTokenResponse convert(Map<String, Object> source) {
        String accessToken = getParameterValue(source, "access_token");
        OAuth2AccessToken.TokenType accessTokenType = getAccessTokenType(source);
        long expiresIn = getExpiresIn(source);
        Set<String> scopes = getScopes(source);
        String refreshToken = getParameterValue(source, "refresh_token");
        Map<String, Object> additionalParameters = new LinkedHashMap();
        Iterator var9 = source.entrySet().iterator();

        while(var9.hasNext()) {
            Map.Entry<String, Object> entry = (Map.Entry)var9.next();
            if (!TOKEN_RESPONSE_PARAMETER_NAMES.contains(entry.getKey())) {
                additionalParameters.put((String)entry.getKey(), entry.getValue());
            }
        }

        return OAuth2AccessTokenResponse
                .withToken(accessToken)
                .tokenType(accessTokenType)
                .expiresIn(expiresIn)
                .scopes(scopes)
                .refreshToken(refreshToken)
                .additionalParameters(additionalParameters).build();
    }

    /**
     * Function finds token type in map of response parameters and converts it to TokenType object
     * @param tokenResponseParameters - map of response parameters
     * @return OAuth2AccessToken.TokenType if it found one of specified token types, null otherwise
     */
    private OAuth2AccessToken.TokenType getAccessTokenType(Map<String, Object> tokenResponseParameters) {
        if (availableTokenTypes == null) return OAuth2AccessToken.TokenType.BEARER;

        String tokenType = getParameterValue(tokenResponseParameters, "token_type");
        if (tokenType == null) return null;

        for (String tokenTypeToCompare : availableTokenTypes) {
            if (tokenTypeToCompare.equalsIgnoreCase(tokenType)) return OAuth2AccessToken.TokenType.BEARER;
        }

        return null;
    }

    /**
     * @see org.springframework.security.oauth2.core.endpoint.DefaultMapOAuth2AccessTokenResponseConverter#getExpiresIn(Map)
     */
    private long getExpiresIn(Map<String, Object> tokenResponseParameters) {
        return getParameterValue(tokenResponseParameters, "expires_in", 0L);
    }

    /**
     * @see org.springframework.security.oauth2.core.endpoint.DefaultMapOAuth2AccessTokenResponseConverter#getScopes(Map)
     */
    private Set<String> getScopes(Map<String, Object> tokenResponseParameters) {
        if (tokenResponseParameters.containsKey("scope")) {
            String scope = getParameterValue(tokenResponseParameters, "scope");
            return new HashSet(Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")));
        } else {
            return Collections.emptySet();
        }
    }

    /**
     * @see org.springframework.security.oauth2.core.endpoint.DefaultMapOAuth2AccessTokenResponseConverter#getParameterValue(Map, String)
     */
    private String getParameterValue(Map<String, Object> tokenResponseParameters, String parameterName) {
        Object obj = tokenResponseParameters.get(parameterName);
        return obj != null ? obj.toString() : null;
    }

    /**
     * @see org.springframework.security.oauth2.core.endpoint.DefaultMapOAuth2AccessTokenResponseConverter#getParameterValue(Map, String, long)
     */
    private long getParameterValue(Map<String, Object> tokenResponseParameters, 
                                   String parameterName, long defaultValue) {
        long parameterValue = defaultValue;
        Object obj = tokenResponseParameters.get(parameterName);
        if (obj != null) {
            if (obj.getClass() == Long.class) {
                parameterValue = (Long)obj;
            } else if (obj.getClass() == Integer.class) {
                parameterValue = (long)(Integer)obj;
            } else {
                try {
                    parameterValue = Long.parseLong(obj.toString());
                } catch (NumberFormatException var8) {
                }
            }
        }

        return parameterValue;
    }
}
