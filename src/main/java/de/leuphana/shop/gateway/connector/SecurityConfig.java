package de.leuphana.shop.gateway.connector;

import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring()
            .antMatchers(HttpMethod.GET, "/articles/**")
            .antMatchers("/carts/**")
            .antMatchers("/authentication/authenticate")
            .antMatchers(HttpMethod.POST, "/orders");
    }

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
            .csrf().disable()
            .addFilterBefore(new AuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
			.authorizeRequests()
			.anyRequest().authenticated();
    }
}