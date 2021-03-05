package de.leuphana.shop.gateway.connector;

import java.io.IOException;
import java.util.Collection;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import de.leuphana.shop.authenticationmicroservice.component.behaviour.AuthenticationService;
import de.leuphana.shop.authenticationmicroservice.component.structure.IncorrectAuthenticationTokenException;

public class AuthenticationFilter extends GenericFilterBean {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        AuthenticationService authenticationService = (AuthenticationService) GatewayServiceApplication
                .getApplicationContext().getBean("authenticationService");

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String authorizationHeader = httpRequest.getHeader("Authorization");

        if(authorizationHeader == null) {
            httpResponse.setStatus(401);
        } else {
            String[] authorizationHeaderParts = authorizationHeader.split(" ");

            if (authorizationHeaderParts.length != 2) {
                httpResponse.setStatus(401);
            } else {
                try {
                    authenticationService.verifyToken(authorizationHeaderParts[1]);
                    Authentication authentication = new Authentication() {

                        private static final long serialVersionUID = 1L;

                        @Override
                        public String getName() {
                            // TODO Auto-generated method stub
                            return null;
                        }

                        @Override
                        public Collection<? extends GrantedAuthority> getAuthorities() {
                            // TODO Auto-generated method stub
                            return null;
                        }

                        @Override
                        public Object getCredentials() {
                            // TODO Auto-generated method stub
                            return null;
                        }

                        @Override
                        public Object getDetails() {
                            return null;
                        }

                        @Override
                        public Object getPrincipal() {
                            return null;
                        }

                        @Override
                        public boolean isAuthenticated() {
                            return true;
                        }

                        @Override
                        public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
                            // TODO Auto-generated method stub
                        }
                        
                    };

                    SecurityContextHolder.getContext().setAuthentication(authentication);
                } catch (IncorrectAuthenticationTokenException e) {}

                chain.doFilter(request, response);
            }
        }
    }
}
