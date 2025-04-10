package com.artlighter.ebayoauth2client.ebay;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.web.SecurityFilterChain;

import static org.assertj.core.api.Assertions.assertThat;

public class SpringOAuth2eBayClientConfigurationTests {
    private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(SpringOAuth2eBayClientConfiguration.class));

    @Test
    public void NoeBayClientRegistrationProperties_ConfigurationDoesntAddFilter() {
        runner.withUserConfiguration(UserConfiguration.class).run((context) -> {
            assertThat(context).doesNotHaveBean(FilterRegistrationBean.class);
        });
    }

    @Test
    public void NeededRepositoriesDontExist_ConfigurationDoesntAddFilter() {
        runner.withPropertyValues("spring.security.oauth2.client.registration.ebay.authorization-code-redirect-uri",
                "uri").run((context) -> {
           assertThat(context).doesNotHaveBean(FilterRegistrationBean.class);
        });
    }

    @Test
    public void RepositoriesConfiguredAndPropertyExists_ConfigurationInitializesFilter() {
        runner.withPropertyValues("spring.security.oauth2.client.registration.ebay.authorization-code-redirect-uri",
                "uri")
                .withUserConfiguration(UserConfiguration.class)
                .run(context -> {
                    assertThat(context).hasSingleBean(FilterRegistrationBean.class);
                });
    }

    @Configuration(proxyBeanMethods = false)
    @EnableWebSecurity
    static class UserConfiguration {
        @Bean
        public ClientRegistrationRepository clientRegistrationRepository() {
            return new InMemoryClientRegistrationRepository(ClientRegistration
                    .withRegistrationId("ebay")
                    .clientId("123")
                    .clientSecret("s")
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUri("redirect")
                    .authorizationUri("auth")
                    .tokenUri("token")
                    .build());
        }

        @Bean
        public OAuth2AuthorizedClientService authorizedClientService(
                ClientRegistrationRepository clientRegistrationRepository) {
            return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository);
        }

        @Bean
        public OAuth2AuthorizedClientRepository authorizedClientRepository(
                OAuth2AuthorizedClientService authorizedClientService) {
            return new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(authorizedClientService);
        }

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
            return httpSecurity.oauth2Client(Customizer.withDefaults()).build();
        }
    }
}
