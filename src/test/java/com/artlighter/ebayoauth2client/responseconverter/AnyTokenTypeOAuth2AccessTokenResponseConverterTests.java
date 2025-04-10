package com.artlighter.ebayoauth2client.responseconverter;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class AnyTokenTypeOAuth2AccessTokenResponseConverterTests {

    @Test
    public void ConverterHasNoSpecifiedTokenTypes_AcceptsAnyTokenType_ReturnsValidTokenResponsesWithBearerTokenType() {
        OAuth2AccessTokenResponse expectedTokenResponse = getTestTokenResponse(getTestResponseAsMap(""));
        AnyTokenTypeOAuth2AccessTokenResponseConverter converter = new AnyTokenTypeOAuth2AccessTokenResponseConverter();

        OAuth2AccessTokenResponse actualTokenResponse = converter.convert(getTestResponseAsMap("Bearer"));

        check(expectedTokenResponse, actualTokenResponse);


        actualTokenResponse = converter.convert(getTestResponseAsMap("User Access Token"));

        check(expectedTokenResponse, actualTokenResponse);


        actualTokenResponse = converter.convert(getTestResponseAsMap("random1235"));

        check(expectedTokenResponse, actualTokenResponse);
    }

    @Test
    public void ConverterHasSpecifiedTokenTypes_AcceptsSpecifiedTypes_ReturnsValidTokenResponsesWithBearerTokenType() {
        OAuth2AccessTokenResponse expectedTokenResponse = getTestTokenResponse(getTestResponseAsMap(""));
        AnyTokenTypeOAuth2AccessTokenResponseConverter converter =
                new AnyTokenTypeOAuth2AccessTokenResponseConverter("Bearer", "User Access Token");

        OAuth2AccessTokenResponse actualTokenResponse = converter.convert(getTestResponseAsMap("Bearer"));

        check(expectedTokenResponse, actualTokenResponse);


        actualTokenResponse = converter.convert(getTestResponseAsMap("User Access Token"));

        check(expectedTokenResponse, actualTokenResponse);
    }

    @Test
    public void ConverterHasSpecifiedTokenTypes_AcceptsNonSpecifiedTypes_ThrowsException() {
        AnyTokenTypeOAuth2AccessTokenResponseConverter converter =
                new AnyTokenTypeOAuth2AccessTokenResponseConverter("Bearer", "User Access Token");

        Assertions.assertThrows(Exception.class, () -> converter.convert(getTestResponseAsMap("random55")));
    }

    private void check(OAuth2AccessTokenResponse expected, OAuth2AccessTokenResponse actual) {
        Assertions.assertNotNull(expected);

        OAuth2AccessToken expectedAccessToken = expected.getAccessToken();
        OAuth2AccessToken actualAccessToken = actual.getAccessToken();
        Assertions.assertEquals(expectedAccessToken.getTokenType(), actualAccessToken.getTokenType());
        Assertions.assertEquals(expectedAccessToken.getTokenValue(), actualAccessToken.getTokenValue());
        Assertions.assertEquals(expectedAccessToken.getScopes(), actualAccessToken.getScopes());

        OAuth2RefreshToken expectedRefreshToken = expected.getRefreshToken();
        OAuth2RefreshToken actualRefreshToken = actual.getRefreshToken();
        Assertions.assertEquals(expectedRefreshToken.getTokenValue(), actualRefreshToken.getTokenValue());
    }

    private Map<String, Object> getTestResponseAsMap(String tokenType) {
        Map<String, Object> response = new HashMap<>();

        response.put("access_token", "token");
        response.put("refresh_token", "refresh_token");
        response.put("token_type", tokenType);
        response.put("expires_in", 14895L);
        response.put("scope", "scope1 scope2");

        return response;
    }

    private OAuth2AccessTokenResponse getTestTokenResponse(Map<String, Object> responseMap) {
        return OAuth2AccessTokenResponse
                .withToken((String) responseMap.get("access_token"))
                .tokenType(OAuth2AccessToken.TokenType.BEARER)
                .expiresIn((Long) responseMap.get("expires_in"))
                .scopes(Set.copyOf(Arrays.asList(responseMap.get("scope").toString().split(" "))))
                .refreshToken((String) responseMap.get("refresh_token")).build();
    }

}
