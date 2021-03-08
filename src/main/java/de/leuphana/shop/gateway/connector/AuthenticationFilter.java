package de.leuphana.shop.gateway.connector;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.filter.OncePerRequestFilter;

import de.leuphana.shop.authenticationmicroservice.component.behaviour.AuthenticationService;
import de.leuphana.shop.authenticationmicroservice.component.structure.IncorrectAuthenticationTokenException;
public class AuthenticationFilter extends OncePerRequestFilter {

    @Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
	
        AuthenticationService authenticationService = (AuthenticationService) GatewayServiceApplication.getApplicationContext().getBean("authenticationService");

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String authorizationHeader = httpRequest.getHeader("Authorization");

        if(authorizationHeader == null) {
            throw new AuthenticationCredentialsNotFoundException("Missing auth header");
        } else {
            String[] authorizationHeaderParts = authorizationHeader.split(" ");

            if (authorizationHeaderParts.length != 2) {
                throw new AuthenticationCredentialsNotFoundException("Auth header type not specified");
            } else {
                try {
                    authenticationService.verifyToken(authorizationHeaderParts[1]);

                    List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
                    authorities.add(new SimpleGrantedAuthority("DEFAULT"));

                    User user = new User("1", "1", true, true, true, true, authorities);

                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user, null, authorities);
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);

                    chain.doFilter(request, response);
                } catch(IncorrectAuthenticationTokenException exception) {
                    throw new AuthenticationServiceException("Invalid or expired token");
                }
            }
        }
    }
}
