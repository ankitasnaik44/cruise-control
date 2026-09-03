/*
 * Copyright 2020 LinkedIn Corp. Licensed under the BSD 2-Clause License (the "License"). See License in the project root for license information.
 */

package com.linkedin.kafka.cruisecontrol.servlet.security.spnego;

import com.linkedin.kafka.cruisecontrol.servlet.security.DummyAuthorizationService;
import com.linkedin.kafka.cruisecontrol.servlet.security.UserStoreAuthorizationService;
import org.apache.kafka.common.security.kerberos.KerberosName;
import org.apache.kafka.common.security.kerberos.KerberosShortNamer;
import org.eclipse.jetty.security.IdentityService;
import org.eclipse.jetty.security.LoginService;
import org.eclipse.jetty.security.PropertyUserStore;
import org.eclipse.jetty.security.RoleDelegateUserIdentity;
import org.eclipse.jetty.security.SPNEGOLoginService;
import org.eclipse.jetty.security.SPNEGOUserPrincipal;
import org.eclipse.jetty.security.UserIdentity;
import org.eclipse.jetty.util.component.ContainerLifeCycle;
import org.eclipse.jetty.util.component.LifeCycle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.security.auth.Subject;
import jakarta.servlet.http.HttpServletRequest;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Session;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.function.Function;

/**
 * This class is needed in order to manage the {@link AuthorizationService}.
 * For instance if the AuthorizationService holds a {@link PropertyUserStore} then it would load
 * users from the store during the {@link PropertyUserStore#start()} method.
 *
 * @see UserStoreAuthorizationService
 */
public class SpnegoLoginServiceWithAuthServiceLifecycle extends ContainerLifeCycle implements LoginService {

  private static final Logger LOG = LoggerFactory.getLogger(SpnegoLoginServiceWithAuthServiceLifecycle.class);
  private final SPNEGOLoginService _spnegoLoginService;
  private final AuthorizationService _authorizationService;
  private final KerberosShortNamer _kerberosShortNamer;

  public SpnegoLoginServiceWithAuthServiceLifecycle(String realm, AuthorizationService authorizationService, List<String> principalToLocalRules) {
    _spnegoLoginService = new SPNEGOLoginService(realm, new DummyLoginService());
    _authorizationService = authorizationService;
    _kerberosShortNamer = principalToLocalRules == null || principalToLocalRules.isEmpty()
            ? null
            : KerberosShortNamer.fromUnparsedRules(realm, principalToLocalRules);
  }

  @Override
  protected void doStart() throws Exception {
    addBean(_spnegoLoginService);
    addBean(_authorizationService);
    super.doStart();
  }

  @Override
  public String getName() {
    return _spnegoLoginService.getName();
  }

  @Override
  public UserIdentity login(String username, Object credentials, Request request, Function<Boolean, Session> getOrCreateSession) {
    // Perform SPNEGO authentication via the delegate
    RoleDelegateUserIdentity spnegoIdentity = (RoleDelegateUserIdentity) _spnegoLoginService.login(username, credentials, request, getOrCreateSession);
    if (spnegoIdentity == null) {
      return null;
    }

    SPNEGOUserPrincipal userPrincipal = (SPNEGOUserPrincipal) spnegoIdentity.getUserPrincipal();
    String fullPrincipal = userPrincipal.getName();
    LOG.debug("User logged in with principal {}", fullPrincipal);

    // Derive short name
    String userShortname = getSpnegoUserPrincipalShortname(fullPrincipal);

    // Resolve authorization identity
    HttpServletRequest httpRequest = (HttpServletRequest) request.getAttribute(
        com.linkedin.kafka.cruisecontrol.servlet.security.jwt.JwtAuthenticator.HTTP_SERVLET_REQUEST_ATTRIBUTE);
    UserIdentity roleDelegate = httpRequest != null
        ? _authorizationService.getUserIdentity(httpRequest, userShortname)
        : null;

    SPNEGOUserPrincipal shortPrincipal = new SPNEGOUserPrincipal(userShortname, userPrincipal.getEncodedToken());
    return new RoleDelegateUserIdentity(spnegoIdentity.getSubject(), shortPrincipal, roleDelegate);
  }

  @Override
  public boolean validate(UserIdentity user) {
    return _spnegoLoginService.validate(user);
  }

  @Override
  public IdentityService getIdentityService() {
    return _spnegoLoginService.getIdentityService();
  }

  @Override
  public void setIdentityService(IdentityService service) {
    _spnegoLoginService.setIdentityService(service);
  }

  @Override
  public void logout(UserIdentity user) {
    _spnegoLoginService.logout(user);
  }

  public void setServiceName(String serviceName) {
    _spnegoLoginService.setServiceName(serviceName);
  }

  public void setHostName(String hostName) {
    _spnegoLoginService.setHostName(hostName);
  }

  public void setKeyTabPath(Path keyTabFile) {
    _spnegoLoginService.setKeyTabPath(keyTabFile);
  }

  // Expose isEstablished check through the identity
  public boolean isEstablished(UserIdentity identity) {
    return identity instanceof RoleDelegateUserIdentity rdi && rdi.isEstablished();
  }

  private String getSpnegoUserPrincipalShortname(String fullPrincipal) {
    PrincipalName userPrincipalName = PrincipalValidator.parsePrincipal("", fullPrincipal);

    if (_kerberosShortNamer == null) {
      return userPrincipalName.getPrimary();
    }

    try {
      String userShortname = _kerberosShortNamer.shortName(new KerberosName(userPrincipalName.getPrimary(),
              userPrincipalName.getInstance(), userPrincipalName.getRealm()));
      LOG.debug("Principal {} was shortened to {}", userPrincipalName, userShortname);
      return userShortname;
    } catch (IOException e) {
      throw new RuntimeException("Could not generate short name for principal " + userPrincipalName, e);
    }
  }

  /**
   * A minimal LoginService used as the inner delegate for SPNEGOLoginService.
   * SPNEGOLoginService requires a LoginService to look up user identity after SPNEGO is established.
   * This no-op implementation is replaced by our own authorization logic.
   */
  private static class DummyLoginService implements LoginService {
    @Override
    public String getName() {
      return "DummyLoginService";
    }

    @Override
    public UserIdentity login(String username, Object credentials, Request request, Function<Boolean, Session> getOrCreateSession) {
      return UserIdentity.from(new Subject(), () -> username);
    }

    @Override
    public boolean validate(UserIdentity user) {
      return false;
    }

    @Override
    public IdentityService getIdentityService() {
      return null;
    }

    @Override
    public void setIdentityService(IdentityService service) {
    }

    @Override
    public void logout(UserIdentity user) {
    }
  }
}
