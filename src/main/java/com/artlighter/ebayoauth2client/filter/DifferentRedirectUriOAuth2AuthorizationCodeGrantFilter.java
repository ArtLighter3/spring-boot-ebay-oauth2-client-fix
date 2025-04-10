package com.artlighter.ebayoauth2client.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.*;

/**
 * Copy of OAuth2AuthorizationCodeGrantFilter, but instead it triggers even if redirect_uri parameter of authorization
 * code request to third-party API actually differs from URL to which that API redirects after user's consent.
 *
 * For example, eBay OAuth2 flow uses redirect_uri as an identifier for current app's registered URLs but redirects
 * to another access/failure URL after consent. Spring Boot OAuth2 flow only accepts retrieved
 * authorization code on redirect_uri URL (specifically, OAuth2AuthorizationCodeGrantFilter does that).
 */
public class DifferentRedirectUriOAuth2AuthorizationCodeGrantFilter extends OncePerRequestFilter {
    private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
            .getContextHolderStrategy();

    private final ClientRegistrationRepository clientRegistrationRepository;

    private final OAuth2AuthorizedClientRepository authorizedClientRepository;

    private final AuthenticationManager authenticationManager;

    private AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository = new HttpSessionOAuth2AuthorizationRequestRepository();

    private final AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();

    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    private RequestCache requestCache = new HttpSessionRequestCache();
    private Map<String, String> authorizationCodeURIs;

    /**
     * Constructor
     * @param clientRegistrationRepository the repository of client registrations
     * @param authorizedClientRepository the authorized client repository
     * @param authenticationManager the authentication manager
     * @param authorizationCodeURIs Map of URIs to which requesting API actually redirects with authorization code.
     *                              Keys are Client Registration IDs of OAuth2 providers,
     *                              values are URIs associated with respective providers
     *                                (if null, default redirect_uri will be used for any OAuth2 provider).
     */
    public DifferentRedirectUriOAuth2AuthorizationCodeGrantFilter(ClientRegistrationRepository clientRegistrationRepository,
                                                                  OAuth2AuthorizedClientRepository authorizedClientRepository,
                                                                  AuthenticationManager authenticationManager,
                                                                  @Nullable Map<String, String> authorizationCodeURIs) {
        Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
        Assert.notNull(authorizedClientRepository, "authorizedClientRepository cannot be null");
        Assert.notNull(authenticationManager, "authenticationManager cannot be null");
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.authorizedClientRepository = authorizedClientRepository;
        this.authenticationManager = authenticationManager;
        this.authorizationCodeURIs = authorizationCodeURIs;
    }

    /**
     * Sets the repository for stored {@link OAuth2AuthorizationRequest}'s.
     * @param authorizationRequestRepository the repository for stored
     * {@link OAuth2AuthorizationRequest}'s
     */
    public final void setAuthorizationRequestRepository(
            AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository) {
        Assert.notNull(authorizationRequestRepository, "authorizationRequestRepository cannot be null");
        this.authorizationRequestRepository = authorizationRequestRepository;
    }

    /**
     * Sets the {@link RequestCache} used for loading a previously saved request (if
     * available) and replaying it after completing the processing of the OAuth 2.0
     * Authorization Response.
     * @param requestCache the cache used for loading a previously saved request (if
     * available)
     */
    public final void setRequestCache(RequestCache requestCache) {
        Assert.notNull(requestCache, "requestCache cannot be null");
        this.requestCache = requestCache;
    }

    /**
     * Sets the {@link SecurityContextHolderStrategy} to use. The default action is to use
     * the {@link SecurityContextHolderStrategy} stored in {@link SecurityContextHolder}.
     */
    public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
        Assert.notNull(securityContextHolderStrategy, "securityContextHolderStrategy cannot be null");
        this.securityContextHolderStrategy = securityContextHolderStrategy;
    }

    public Map<String, String> getAuthorizationCodeURIs() {
        return authorizationCodeURIs;
    }

    public void setAuthorizationCodeURIs(Map<String, String> authorizationCodeURIs) {
        this.authorizationCodeURIs = authorizationCodeURIs;
    }

    public AuthenticationManager getAuthenticationManager() {
        return authenticationManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (matchesAuthorizationResponse(request)) {
            processAuthorizationResponse(request, response);
            return;
        }
        filterChain.doFilter(request, response);
    }

    private boolean matchesAuthorizationResponse(HttpServletRequest request) {
        MultiValueMap<String, String> params = toMultiMap(request.getParameterMap());
        if (!isAuthorizationResponse(params)) {
            return false;
        }
        OAuth2AuthorizationRequest authorizationRequest = this.authorizationRequestRepository
                .loadAuthorizationRequest(request);
        if (authorizationRequest == null) {
            return false;
        }
        // Compare
        String authorizationCodeUriStr = getAuthorizationCodeURI(authorizationRequest);
        UriComponents requestUri = UriComponentsBuilder.fromUriString(UrlUtils.buildFullRequestUrl(request)).build();
        UriComponents authorizationCodeUri = UriComponentsBuilder.fromUriString(expandRedirectUri(request,
                authorizationRequest.getAttribute(OAuth2ParameterNames.REGISTRATION_ID), authorizationCodeUriStr))
                .build();
        Set<Map.Entry<String, List<String>>> requestUriParameters = new LinkedHashSet<>(
                requestUri.getQueryParams().entrySet());
        Set<Map.Entry<String, List<String>>> redirectUriParameters = new LinkedHashSet<>(
                authorizationCodeUri.getQueryParams().entrySet());
        // Remove the additional request parameters (if any) from the authorization
        // response (request)
        // before doing an exact comparison with the authorizationCodeUri
        // parameters (if any)
        requestUriParameters.retainAll(redirectUriParameters);
        if (Objects.equals(requestUri.getScheme(), authorizationCodeUri.getScheme())
                && Objects.equals(requestUri.getUserInfo(), authorizationCodeUri.getUserInfo())
                && Objects.equals(requestUri.getHost(), authorizationCodeUri.getHost())
                && Objects.equals(requestUri.getPort(), authorizationCodeUri.getPort())
                && Objects.equals(requestUri.getPath(), authorizationCodeUri.getPath())
                && Objects.equals(requestUriParameters.toString(), redirectUriParameters.toString())) {
            return true;
        }
        return false;
    }

    private void processAuthorizationResponse(HttpServletRequest request, HttpServletResponse response)
            throws IOException {

        OAuth2AuthorizationRequest authorizationRequest = this.authorizationRequestRepository
                .removeAuthorizationRequest(request, response);
        String registrationId = authorizationRequest.getAttribute(OAuth2ParameterNames.REGISTRATION_ID);
        ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);
        MultiValueMap<String, String> params = toMultiMap(request.getParameterMap());
        String redirectUri = UrlUtils.buildFullRequestUrl(request);
        OAuth2AuthorizationResponse authorizationResponse = convert(params, redirectUri);
        OAuth2AuthorizationCodeAuthenticationToken authenticationRequest = new OAuth2AuthorizationCodeAuthenticationToken(
                clientRegistration, new OAuth2AuthorizationExchange(authorizationRequest, authorizationResponse));
        authenticationRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));
        OAuth2AuthorizationCodeAuthenticationToken authenticationResult;
        try {
            authenticationResult = (OAuth2AuthorizationCodeAuthenticationToken) this.authenticationManager
                    .authenticate(authenticationRequest);
        }
        catch (OAuth2AuthorizationException ex) {
            OAuth2Error error = ex.getError();

            String authorizationCodeUriStr = getAuthorizationCodeURI(authorizationRequest);
            UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromUriString(expandRedirectUri(request,
                            registrationId, authorizationCodeUriStr))
                    .queryParam(OAuth2ParameterNames.ERROR, error.getErrorCode());

            if (StringUtils.hasLength(error.getDescription())) {
                uriBuilder.queryParam(OAuth2ParameterNames.ERROR_DESCRIPTION, error.getDescription());
            }
            if (StringUtils.hasLength(error.getUri())) {
                uriBuilder.queryParam(OAuth2ParameterNames.ERROR_URI, error.getUri());
            }
            this.redirectStrategy.sendRedirect(request, response, uriBuilder.build().encode().toString());
            return;
        }
        Authentication currentAuthentication = this.securityContextHolderStrategy.getContext().getAuthentication();
        String principalName = (currentAuthentication != null) ? currentAuthentication.getName() : "anonymousUser";
        OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
                authenticationResult.getClientRegistration(), principalName, authenticationResult.getAccessToken(),
                authenticationResult.getRefreshToken());
        this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, currentAuthentication, request,
                response);
        String redirectUrl = expandRedirectUri(request, registrationId, getAuthorizationCodeURI(authorizationRequest));
        SavedRequest savedRequest = this.requestCache.getRequest(request, response);
        if (savedRequest != null) {
            redirectUrl = savedRequest.getRedirectUrl();
            this.requestCache.removeRequest(request, response);
        }
        this.redirectStrategy.sendRedirect(request, response, redirectUrl);
    }

    private String getAuthorizationCodeURI(OAuth2AuthorizationRequest authorizationRequest) {
        String authorizationCodeUriStr = authorizationCodeURIs != null ?
                authorizationCodeURIs.get(authorizationRequest.getAttribute(OAuth2ParameterNames.REGISTRATION_ID)) :
                null;
        if (authorizationCodeUriStr == null) authorizationCodeUriStr = authorizationRequest.getRedirectUri();

        return authorizationCodeUriStr;
    }

    private String expandRedirectUri(HttpServletRequest request, String clientRegistrationId,
                                            String redirectUriStr) {
        Map<String, String> uriVariables = new HashMap<>();
        uriVariables.put("registrationId", clientRegistrationId);
        // @formatter:off
        UriComponents uriComponents = UriComponentsBuilder.fromHttpUrl(UrlUtils.buildFullRequestUrl(request))
                .replacePath(request.getContextPath())
                .replaceQuery(null)
                .fragment(null)
                .build();
        // @formatter:on
        String scheme = uriComponents.getScheme();
        uriVariables.put("baseScheme", (scheme != null) ? scheme : "");
        String host = uriComponents.getHost();
        uriVariables.put("baseHost", (host != null) ? host : "");
        // following logic is based on HierarchicalUriComponents#toUriString()
        int port = uriComponents.getPort();
        uriVariables.put("basePort", (port == -1) ? "" : ":" + port);
        String path = uriComponents.getPath();
        if (StringUtils.hasLength(path)) {
            if (path.charAt(0) != '/') {
                path = '/' + path;
            }
        }
        uriVariables.put("basePath", (path != null) ? path : "");
        uriVariables.put("baseUrl", uriComponents.toUriString());
        return UriComponentsBuilder.fromUriString(redirectUriStr).buildAndExpand(uriVariables).toUriString();
    }

    private MultiValueMap<String, String> toMultiMap(Map<String, String[]> map) {
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>(map.size());
        map.forEach((key, values) -> {
            if (values.length > 0) {
                for (String value : values) {
                    params.add(key, value);
                }
            }
        });
        return params;
    }

    private boolean isAuthorizationResponse(MultiValueMap<String, String> request) {
        return isAuthorizationResponseSuccess(request) || isAuthorizationResponseError(request);
    }

    private boolean isAuthorizationResponseSuccess(MultiValueMap<String, String> request) {
        return StringUtils.hasText(request.getFirst(OAuth2ParameterNames.CODE))
                && StringUtils.hasText(request.getFirst(OAuth2ParameterNames.STATE));
    }

    private boolean isAuthorizationResponseError(MultiValueMap<String, String> request) {
        return StringUtils.hasText(request.getFirst(OAuth2ParameterNames.ERROR))
                && StringUtils.hasText(request.getFirst(OAuth2ParameterNames.STATE));
    }

    private OAuth2AuthorizationResponse convert(MultiValueMap<String, String> request, String redirectUri) {
        String code = request.getFirst(OAuth2ParameterNames.CODE);
        String errorCode = request.getFirst(OAuth2ParameterNames.ERROR);
        String state = request.getFirst(OAuth2ParameterNames.STATE);
        if (StringUtils.hasText(code)) {
            return OAuth2AuthorizationResponse.success(code).redirectUri(redirectUri).state(state).build();
        }
        String errorDescription = request.getFirst(OAuth2ParameterNames.ERROR_DESCRIPTION);
        String errorUri = request.getFirst(OAuth2ParameterNames.ERROR_URI);
        // @formatter:off
        return OAuth2AuthorizationResponse.error(errorCode)
                .redirectUri(redirectUri)
                .errorDescription(errorDescription)
                .errorUri(errorUri)
                .state(state)
                .build();
        // @formatter:on
    }
}
