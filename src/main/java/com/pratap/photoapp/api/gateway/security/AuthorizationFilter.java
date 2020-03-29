package com.pratap.photoapp.api.gateway.security;

import java.io.IOException;
import java.util.ArrayList;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import io.jsonwebtoken.Jwts;
/**
 * <h1>AuthorizationFilter</h1>
 * <p>AuthorizationFilter, validate the JWT token, provided in to the header<p>
 * <b>case -1:</b> if the request is valid, only request pass through API gateway
 * <b>case -2:</b> if not, request not pass through API gateway
 * @author Pratap Narayan
 */
public class AuthorizationFilter extends BasicAuthenticationFilter {

	Environment environment;
	
	public AuthorizationFilter(AuthenticationManager authenticationManager, Environment environment) {
		super(authenticationManager);
		this.environment = environment;
	}
	
	@Override
    protected void doFilterInternal(HttpServletRequest req,
            HttpServletResponse res,
            FilterChain chain) throws IOException, ServletException {

        String authorizationHeader = req.getHeader(environment.getProperty("authorization.token.header.name"));

        if (authorizationHeader == null || !authorizationHeader.startsWith(environment.getProperty("authorization.token.header.prefix"))) {
            chain.doFilter(req, res);
            return;
        }

        UsernamePasswordAuthenticationToken authentication = getAuthentication(req);
       
        SecurityContextHolder.getContext().setAuthentication(authentication);
        chain.doFilter(req, res);
    }
	
	private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest req) {
        String authorizationHeader = req.getHeader(environment.getProperty("authorization.token.header.name"));
   
         if (authorizationHeader == null) {
             return null;
         }

         String token = authorizationHeader.replace(environment.getProperty("authorization.token.header.prefix"), "");

         String userId = Jwts.parser()
                 .setSigningKey(environment.getProperty("token.secret"))
                 .parseClaimsJws(token)
                 .getBody()
                 .getSubject();

         if (userId == null) {
             return null;
         }
   
         return new UsernamePasswordAuthenticationToken(userId, null, new ArrayList<>());

     }

}
