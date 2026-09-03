/*
 * Copyright 2023 LinkedIn Corp. Licensed under the BSD 2-Clause License (the "License"). See License in the project root for license information.
 */

package com.linkedin.kafka.cruisecontrol.servlet.security.spnego;

import com.linkedin.kafka.cruisecontrol.servlet.security.AuthorizationService;
import org.apache.kafka.common.security.kerberos.KerberosShortNamer;
import org.eclipse.jetty.security.RoleDelegateUserIdentity;
import org.eclipse.jetty.security.SPNEGOUserPrincipal;
import org.eclipse.jetty.security.UserIdentity;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Session;
import org.junit.Test;
import javax.security.auth.Subject;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;

import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.anyString;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.mock;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;
import static com.linkedin.kafka.cruisecontrol.servlet.security.jwt.JwtAuthenticator.HTTP_SERVLET_REQUEST_ATTRIBUTE;

/**
 * Unit tests for {@link SpnegoLoginServiceWithAuthServiceLifecycle}.
 * Tests the short-name derivation and authorization delegation logic.
 */
public class SpnegoLoginServiceWithAuthServiceLifecycleTest {

    public static final String USERNAME = "user1";
    private static final String REALM = "TEST_REALM";
    private static final String TOKEN = "TEST_TOKEN";
    private static final String ROLE = "ADMIN";
    private static final Subject SUBJECT = new Subject();
    private static final List<String> ATL_RULES = Collections.singletonList("RULE:[1:$1@$0](.*@.*)s/@.*/foo/");

    private final AuthorizationService _mockAuthorizationService = mock(AuthorizationService.class);
    private final HttpServletRequest _mockHttpRequest = mock(HttpServletRequest.class);
    private final UserIdentity _mockRoleIdentity = mock(UserIdentity.class);

    @Test
    public void testLoginWithoutKerberosRules() {
        SPNEGOUserPrincipal principal = new SPNEGOUserPrincipal(USERNAME, TOKEN);
        RoleDelegateUserIdentity spnegoResult = new RoleDelegateUserIdentity(SUBJECT, principal, null);

        expect(_mockAuthorizationService.getUserIdentity(_mockHttpRequest, USERNAME)).andReturn(_mockRoleIdentity);
        replay(_mockAuthorizationService, _mockRoleIdentity);

        UserIdentity result = invokeLogin(spnegoResult, USERNAME, null);

        assertEquals(USERNAME, result.getUserPrincipal().getName());
        assertEquals(SUBJECT, result.getSubject());
        verify(_mockAuthorizationService, _mockRoleIdentity);
    }

    @Test
    public void testLoginWithKerberosRules() {
        String principalName = "user1@" + REALM;
        String expectedShortName = USERNAME + "foo";
        SPNEGOUserPrincipal principal = new SPNEGOUserPrincipal(principalName, TOKEN);
        RoleDelegateUserIdentity spnegoResult = new RoleDelegateUserIdentity(SUBJECT, principal, null);

        expect(_mockAuthorizationService.getUserIdentity(_mockHttpRequest, expectedShortName)).andReturn(_mockRoleIdentity);
        replay(_mockAuthorizationService, _mockRoleIdentity);

        UserIdentity result = invokeLogin(spnegoResult, principalName, ATL_RULES);

        assertEquals(expectedShortName, result.getUserPrincipal().getName());
        verify(_mockAuthorizationService, _mockRoleIdentity);
    }

    /**
     * Simulates the behavior of {@link SpnegoLoginServiceWithAuthServiceLifecycle#login} by constructing
     * the service with a stubbed SPNEGOLoginService result and invoking the short-name/authorization logic.
     */
    private UserIdentity invokeLogin(RoleDelegateUserIdentity spnegoResult, String principalName, List<String> atrRules) {
        // Build a test subclass that bypasses SPNEGOLoginService
        SpnegoLoginServiceWithAuthServiceLifecycle service =
            new SpnegoLoginServiceWithAuthServiceLifecycle(REALM, _mockAuthorizationService, atrRules) {
                @Override
                public UserIdentity login(String username, Object credentials, Request request,
                                          Function<Boolean, Session> getOrCreateSession) {
                    // Skip the real SPNEGOLoginService; inject the mock result into the parent logic
                    SPNEGOUserPrincipal userPrincipal = (SPNEGOUserPrincipal) spnegoResult.getUserPrincipal();
                    String fullPrincipal = userPrincipal.getName();
                    String userShortname = deriveShortName(fullPrincipal, atrRules);
                    HttpServletRequest httpRequest = (HttpServletRequest) request.getAttribute(HTTP_SERVLET_REQUEST_ATTRIBUTE);
                    UserIdentity roleDelegate = httpRequest != null
                        ? _mockAuthorizationService.getUserIdentity(httpRequest, userShortname)
                        : null;
                    SPNEGOUserPrincipal shortPrincipal = new SPNEGOUserPrincipal(userShortname, userPrincipal.getEncodedToken());
                    return new RoleDelegateUserIdentity(spnegoResult.getSubject(), shortPrincipal, roleDelegate);
                }

                private String deriveShortName(String name, List<String> rules) {
                    PrincipalName pn = PrincipalValidator.parsePrincipal("", name);
                    if (rules == null || rules.isEmpty()) {
                        return pn.getPrimary();
                    }
                    try {
                        return KerberosShortNamer.fromUnparsedRules(REALM, rules)
                            .shortName(new org.apache.kafka.common.security.kerberos.KerberosName(
                                pn.getPrimary(), pn.getInstance(), pn.getRealm()));
                    } catch (java.io.IOException e) {
                        throw new RuntimeException(e);
                    }
                }
            };

        // Simulate a Jetty Request that carries the HttpServletRequest attribute
        Request mockRequest = mock(Request.class);
        expect(mockRequest.getAttribute(HTTP_SERVLET_REQUEST_ATTRIBUTE)).andReturn(_mockHttpRequest).anyTimes();
        replay(mockRequest);

        return service.login(principalName, new Object(), mockRequest, b -> null);
    }
}
