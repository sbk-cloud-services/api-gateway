package de.leuphana.shop.gateway.connector;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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
                } catch (IncorrectAuthenticationTokenException e) {
                    httpResponse.setStatus(401);
                }

                chain.doFilter(request, response);
            }
        }
    }
}
