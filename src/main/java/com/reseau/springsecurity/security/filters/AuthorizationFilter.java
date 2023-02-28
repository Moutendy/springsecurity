package com.reseau.springsecurity.security.filters;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.reseau.springsecurity.security.utils.JwtUtils;

public class AuthorizationFilter extends OncePerRequestFilter {

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		// TODO Auto-generated method stub
		
		
		   if(request.getServletPath().equals("/apis/auth/login") || request.getServletPath().equals("/apis/auth/refresh")) {

	            filterChain.doFilter(request, response);
	        }
	        else {

	            String authorizationHeader = request.getHeader("Authorization");

	            if(authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {

	                try {

	                    DecodedJWT decodedJWT = JwtUtils.decodeToken(authorizationHeader.substring("Bearer ".length()));

	                    String username = decodedJWT.getSubject();

	                    String role = decodedJWT.getClaim("role").asString();

	                    Collection<SimpleGrantedAuthority> authority = new ArrayList<>();

	                    authority.add(new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()));

	                    UsernamePasswordAuthenticationToken authenticationToken =
	                            new UsernamePasswordAuthenticationToken(username, null, authority);

	                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);

	                    filterChain.doFilter(request, response);

	                }catch(Exception e) {
	                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
	                }
	            }
	            else {
	                filterChain.doFilter(request, response);
	            }
	        }
		
	}

}
