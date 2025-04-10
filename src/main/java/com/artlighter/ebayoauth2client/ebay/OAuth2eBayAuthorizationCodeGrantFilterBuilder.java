package com.artlighter.ebayoauth2client.ebay;

import com.artlighter.ebayoauth2client.filter.DifferentRedirectUriOAuth2AuthorizationCodeGrantFilter;
import com.artlighter.ebayoauth2client.responseconverter.AnyTokenTypeOAuth2AccessTokenResponseConverter;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.client.endpoint.RestClientAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.util.Assert;
import org.springframework.web.client.RestClient;

import java.util.Collections;

/**
 * Builder of DifferentRedirectUriOAuth2AuthorizationCodeGrantFilter that is specifically configured to
 * eBay's OAuth2 client flow
 */
public class OAuth2eBayAuthorizationCodeGrantFilterBuilder {
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final OAuth2AuthorizedClientRepository authorizedClientRepository;

    private String authorizationCodeRedirectUriStr = "{baseUrl}/login/oauth2/code/{registrationId}";
    private String eBayClientRegistrationId = "ebay";

    private OAuth2eBayAuthorizationCodeGrantFilterBuilder(ClientRegistrationRepository clientRegistrationRepository,
                                                         OAuth2AuthorizedClientRepository authorizedClientRepository) {
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.authorizedClientRepository = authorizedClientRepository;
    }

    /**
     * Returns new instance of OAuth2eBayAuthorizationCodeGrantFilterBuilder with specified
     * ClientRegistrationRepository and OAuth2AuthorizedClientRepository for configuring
     * AuthorizationCodeGrantFilter to work with eBay's OAuth2 flow
     * @param clientRegistrationRepository repository of client registrations info for OAuth2 flow
     * @param authorizedClientRepository repository of authorized clients
     * @return new instance of OAuth2eBayAuthorizationCodeGrantFilterBuilder
     */
    public static OAuth2eBayAuthorizationCodeGrantFilterBuilder withRepositories(ClientRegistrationRepository clientRegistrationRepository,
                                                                                 OAuth2AuthorizedClientRepository authorizedClientRepository) {
        Assert.notNull(clientRegistrationRepository, "ClientRegistrationRepository cannot be null");
        Assert.notNull(authorizedClientRepository, "OAuth2AuthorizedClientRepository cannot be null");
        return new
                OAuth2eBayAuthorizationCodeGrantFilterBuilder(clientRegistrationRepository, authorizedClientRepository);
    }

    /**
     * Configures AuthorizationCodeGrantFilter to work with this URI to which eBay redirects with authorization code
     * instead of standard redirect_uri parameter
     * @param uri - eBay's redirect uri with authorization code
     * @return OAuth2eBayAuthorizationCodeGrantFilterBuilder
     */
    public OAuth2eBayAuthorizationCodeGrantFilterBuilder authorizationCodeRedirectUri(String uri) {
        this.authorizationCodeRedirectUriStr = uri;
        return this;
    }

    /**
     * Configures AuthorizationCodeGrantFilter to work with this eBay's client registration ID.
     * 'ebay' is used by default
     * @param clientRegistrationId - eBay's registration ID
     * @return OAuth2eBayAuthorizationCodeGrantFilterBuilder
     */
    public OAuth2eBayAuthorizationCodeGrantFilterBuilder eBayClientRegistrationId(String clientRegistrationId) {
        this.eBayClientRegistrationId = clientRegistrationId;
        return this;
    }

    /**
     * Builds AuthorizationCodeGrantFilter that is configured to work with eBay's redirections
     * @return DifferentRedirectUriOAuth2AuthorizationCodeGrantFilter
     */
    public DifferentRedirectUriOAuth2AuthorizationCodeGrantFilter build() {
        RestClient eBayRestClient = RestClient.builder().messageConverters((messageConverters) -> {
            messageConverters.clear();
            messageConverters.add(new FormHttpMessageConverter());

            OAuth2AccessTokenResponseHttpMessageConverter oauth2Converter =
                    new OAuth2AccessTokenResponseHttpMessageConverter();
            oauth2Converter.setAccessTokenResponseConverter(
                    new AnyTokenTypeOAuth2AccessTokenResponseConverter("User Access Token", "Bearer"));
            messageConverters.add(oauth2Converter);
        }).defaultStatusHandler(new OAuth2ErrorResponseErrorHandler()).build();

        RestClientAuthorizationCodeTokenResponseClient tokenResponseClient =
                new RestClientAuthorizationCodeTokenResponseClient();
        tokenResponseClient.setRestClient(eBayRestClient);

        OAuth2AuthorizationCodeAuthenticationProvider authenticationProvider =
                new OAuth2AuthorizationCodeAuthenticationProvider(tokenResponseClient);


        DifferentRedirectUriOAuth2AuthorizationCodeGrantFilter filter =
                new DifferentRedirectUriOAuth2AuthorizationCodeGrantFilter(clientRegistrationRepository,
                        authorizedClientRepository,
                        new ProviderManager(authenticationProvider),
                        Collections.singletonMap(eBayClientRegistrationId, authorizationCodeRedirectUriStr));
        return filter;
    }
}
