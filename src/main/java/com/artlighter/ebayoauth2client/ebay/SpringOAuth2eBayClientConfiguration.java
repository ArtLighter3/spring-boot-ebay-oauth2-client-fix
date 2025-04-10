package com.artlighter.ebayoauth2client.ebay;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.servlet.OAuth2ClientAutoConfiguration;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;

/**
 * Autoconfiguration that adds new filter configured for eBay's OAuth2 client flow if current application is
 * servlet-type web application and after Spring Boot's default OAuth2 autoconfiguration has been already executed
 */
@AutoConfiguration(after = OAuth2ClientAutoConfiguration.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(name = "spring.security.oauth2.client.registration.ebay.authorization-code-redirect-uri")
public class SpringOAuth2eBayClientConfiguration {

    @Value("${spring.security.oauth2.client.registration.ebay.authorization-code-redirect-uri}")
    private String authorizationCodeRedirectUriStr;

    @Bean
    @ConditionalOnBean({ClientRegistrationRepository.class, OAuth2AuthorizedClientRepository.class})
    public FilterRegistrationBean eBayAuthorizationCodeGrantFilter(ClientRegistrationRepository clientRegistrationRepository,
                                                                   OAuth2AuthorizedClientRepository authorizedClientRepository) {
        FilterRegistrationBean registration = new FilterRegistrationBean();

        registration.setFilter(OAuth2eBayAuthorizationCodeGrantFilterBuilder
                .withRepositories(clientRegistrationRepository, authorizedClientRepository)
                .authorizationCodeRedirectUri(authorizationCodeRedirectUriStr)
                .build());

        return registration;
    }

}
