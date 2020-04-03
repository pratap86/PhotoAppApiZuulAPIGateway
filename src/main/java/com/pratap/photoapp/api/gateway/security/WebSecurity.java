package com.pratap.photoapp.api.gateway.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
/**
 * 
 * @author Pratap Narayan
 *
 */
@EnableWebSecurity
@Configuration
public class WebSecurity extends WebSecurityConfigurerAdapter {

	private final Environment environment;

	@Autowired
	public WebSecurity(Environment environment) {
		this.environment = environment;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		http.csrf().disable(); 
    	http.headers().frameOptions().disable();
    	//permits some resources
    	http.authorizeRequests()
    	.antMatchers(environment.getProperty("api.users.actuator.url.path")).permitAll()
    	.antMatchers(environment.getProperty("api.zuul.actuator.url.path")).permitAll()
    	.antMatchers(environment.getProperty("api.h2console.url.path")).permitAll()
    	.antMatchers(HttpMethod.POST, environment.getProperty("api.registration.url.path")).permitAll()
    	.antMatchers(HttpMethod.POST, environment.getProperty("api.login.url.path")).permitAll()
    	.anyRequest().authenticated()
    	// Registering Authorization Filter
    	.and()
    	.addFilter(new AuthorizationFilter(authenticationManager(), environment));
    	// A http session should be created while a client application connect with server

    	// this make our API is stateless
    	http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
	}
	
	
}
