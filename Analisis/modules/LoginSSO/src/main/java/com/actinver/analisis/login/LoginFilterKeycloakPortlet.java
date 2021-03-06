/**
 * Copyright 2000-present Liferay, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.actinver.analisis.login;

import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;
import com.liferay.portal.security.sso.openid.connect.OpenIdConnectProviderRegistry;
import com.liferay.portal.security.sso.openid.connect.OpenIdConnectServiceHandler;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;

@Component(
		immediate = true,
		property = {
				"servlet-context-name=",
				"servlet-filter-name=Keycloak Login Filter",
				"url-pattern=/c/portal/login"
				},
		service = Filter.class
		)
public class LoginFilterKeycloakPortlet implements Filter {
	
	@Override
	public void init(FilterConfig filterConfig) {
	}
	
	@SuppressWarnings("unchecked")
	@Override
	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse,
			FilterChain filterChain) throws IOException, ServletException {
		try {
			HttpServletRequest request = (HttpServletRequest) servletRequest;
			HttpServletResponse response = (HttpServletResponse) servletResponse;
			
			//Get OpenId Providers
			Collection<String> openIdConnectProviderNames = openIdConnectProviderRegistry.getOpenIdConnectProviderNames();
			if (openIdConnectProviderNames == null || openIdConnectProviderNames.isEmpty()) {
				filterChain.doFilter(servletRequest, servletResponse);
				return;
				}
			
			// Get first OpenID Provider
			String openIdConnectProviderName = openIdConnectProviderNames.iterator().next();
			
			// Request Provider's authentication
			openIdConnectServiceHandler.requestAuthentication(openIdConnectProviderName, request, response);
			
			} catch (Exception e) {
				_log.error("Error in KeycloakLoginFilter: " + e.getMessage(), e);
				} finally {
					filterChain.doFilter(servletRequest, servletResponse);
					}
		}
	
	@Override
	public void destroy() {
	}
	
	@Reference
	private OpenIdConnectProviderRegistry openIdConnectProviderRegistry;
	
	@Reference
	private OpenIdConnectServiceHandler openIdConnectServiceHandler;
	
	private static final Log _log = LogFactoryUtil.getLog(LoginFilterKeycloakPortlet.class);
	}