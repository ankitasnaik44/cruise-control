/*
 * Copyright 2020 LinkedIn Corp. Licensed under the BSD 2-Clause License (the "License"). See License in the project root for license information.
 */

package com.linkedin.kafka.cruisecontrol.servlet.security.jwt;

import com.nimbusds.jwt.SignedJWT;
import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.http.HttpMethod;
import org.eclipse.jetty.http.HttpStatus;
import org.eclipse.jetty.security.AuthenticationState;
import org.eclipse.jetty.security.ServerAuthException;
import org.eclipse.jetty.security.UserIdentity;
import org.eclipse.jetty.security.authentication.LoginAuthenticator;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.util.Callback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.text.ParseException;
import java.util.function.Function;

/**
 * <p>The {@link JwtAuthenticator} adds SSO capabilities to Cruise Control. The expected token is a Json Web Token (JWT).
 * This class should be used with {@link JwtLoginService} as the token check is carried out by that one. This class
 * handles redirects for unauthenticated requests and CORS preflight requests.</p>
 */
public class JwtAuthenticator extends LoginAuthenticator {

  public static final String JWT_TOKEN_REQUEST_ATTRIBUTE = "com.linkedin.kafka.cruisecontrol.JwtTokenAttribute";
  public static final String HTTP_SERVLET_REQUEST_ATTRIBUTE = "com.linkedin.kafka.cruisecontrol.HttpServletRequest";
  public static final Logger JWT_LOGGER = LoggerFactory.getLogger("kafka.cruisecontrol.jwt.logger");

  private static final String METHOD = "JWT";
  static final String BEARER = "Bearer";
  static final String REDIRECT_URL = "{redirectUrl}";

  private final String _cookieName;
  private final Function<Request, String> _authenticationProviderUrlGenerator;

  /**
   * Creates a new {@link JwtAuthenticator} instance with a custom authentication provider url and a cookie name.
   * @param authenticationProviderUrl is the HTTP(S) address of the authentication service.
   * @param cookieName is the cookie name which will contain the token from the authentication service.
   */
  public JwtAuthenticator(String authenticationProviderUrl, String cookieName) {
    _cookieName = cookieName;
    _authenticationProviderUrlGenerator = req -> authenticationProviderUrl.replace(REDIRECT_URL,
        req.getHttpURI().asString() + getOriginalQueryString(req));
  }

  @Override
  public String getAuthenticationType() {
    return METHOD;
  }

  @Override
  public AuthenticationState validateRequest(Request request, Response response, Callback callback) throws ServerAuthException {
    JWT_LOGGER.trace("Authentication request received for " + request.toString());

    // skip authentication for CORS preflight requests
    if (HttpMethod.OPTIONS.is(request.getMethod())) {
      return AuthenticationState.NOT_CHECKED;
    }

    String serializedJWT = getJwtFromBearerAuthorization(request);
    if (serializedJWT == null) {
      serializedJWT = getJwtFromCookie(request);
    }

    if (serializedJWT == null) {
      String loginURL = _authenticationProviderUrlGenerator.apply(request);
      JWT_LOGGER.info("No JWT token found, sending redirect to " + loginURL);
      try {
        Response.sendRedirect(request, response, callback, loginURL);
        return AuthenticationState.SEND_CONTINUE;
      } catch (IOException e) {
        JWT_LOGGER.error("Couldn't authenticate request", e);
        throw new ServerAuthException(e);
      }
    } else {
      try {
        SignedJWT jwtToken = SignedJWT.parse(serializedJWT);
        String userName = jwtToken.getJWTClaimsSet().getSubject();
        request.setAttribute(JWT_TOKEN_REQUEST_ATTRIBUTE, serializedJWT);
        UserIdentity identity = login(userName, jwtToken, request, response);
        if (identity == null) {
          Response.writeError(request, response, callback, HttpStatus.UNAUTHORIZED_401);
          return AuthenticationState.SEND_FAILURE;
        } else {
          return new LoginAuthenticator.UserAuthenticationSucceeded(getAuthenticationType(), identity);
        }
      } catch (ParseException pe) {
        String loginURL = _authenticationProviderUrlGenerator.apply(request);
        JWT_LOGGER.warn("Unable to parse the JWT token, redirecting back to the login page", pe);
        try {
          Response.sendRedirect(request, response, callback, loginURL);
          return AuthenticationState.SEND_CONTINUE;
        } catch (IOException e) {
          throw new ServerAuthException(e);
        }
      }
    }
  }

  String getJwtFromCookie(Request request) {
    // Jetty 12 Request does not expose Cookie objects directly; access through attribute set by ee10 layer
    HttpServletRequest httpRequest = (HttpServletRequest) request.getAttribute(HTTP_SERVLET_REQUEST_ATTRIBUTE);
    if (httpRequest == null) {
      return null;
    }
    Cookie[] cookies = httpRequest.getCookies();
    if (cookies != null) {
      for (Cookie cookie : cookies) {
        if (_cookieName != null && _cookieName.equals(cookie.getName())) {
          JWT_LOGGER.trace(_cookieName + " cookie has been found and is being processed");
          return cookie.getValue();
        }
      }
    }
    return null;
  }

  String getJwtFromBearerAuthorization(Request request) {
    String authorizationHeader = request.getHeaders().get(HttpHeader.AUTHORIZATION);
    if (authorizationHeader == null || !authorizationHeader.startsWith(BEARER)) {
      return null;
    }
    return authorizationHeader.substring(BEARER.length()).trim();
  }

  private String getOriginalQueryString(Request request) {
    String query = request.getHttpURI().getQuery();
    return (query == null) ? "" : "?" + query;
  }
}
