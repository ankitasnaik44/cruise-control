/*
 * Copyright 2020 LinkedIn Corp. Licensed under the BSD 2-Clause License (the "License"). See License in the project root for license information.
 */

package com.linkedin.kafka.cruisecontrol.servlet.security;

import org.eclipse.jetty.security.UserIdentity;
import jakarta.servlet.http.HttpServletRequest;

/**
 * Service for authorizing a user based on their identity (username) and the incoming HTTP request.
 * This interface replaces {@code org.eclipse.jetty.security.authentication.AuthorizationService}
 * which was removed in Jetty 12.
 */
public interface AuthorizationService {

  /**
   * Returns the {@link UserIdentity} for the given username from the incoming HTTP request.
   *
   * @param request the HTTP request
   * @param name    the username to authorize
   * @return the {@link UserIdentity} for the user, or {@code null} if not found
   */
  UserIdentity getUserIdentity(HttpServletRequest request, String name);
}
