package com.reseau.springsecurity.security.filters;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.reseau.springsecurity.model.RoleModel;
import com.reseau.springsecurity.model.UserModel;
import com.reseau.springsecurity.security.utils.JwtUtils;

public class AuthenticationFilter extends UsernamePasswordAuthenticationFilter{

	  private final AuthenticationManager authenticationManager;

	    public AuthenticationFilter(AuthenticationManager authenticationManager) {
	        this.authenticationManager = authenticationManager;
	    }

	    @Override
	    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
	            throws AuthenticationException {

	        String username = request.getParameter("username");
	        String password = request.getParameter("password");

	        UsernamePasswordAuthenticationToken authenticationToken =
	                new UsernamePasswordAuthenticationToken(username, password);

	        return authenticationManager.authenticate(authenticationToken);
	    }


	    @Override
	    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
	                                            Authentication authResult) throws IOException, ServletException {

	        User userDetail = (User) authResult.getPrincipal();

	        List<String> roles = userDetail.getAuthorities().stream().map(GrantedAuthority::getAuthority)
	                .collect(Collectors.toList());

	        // find a better way
	        UserModel user = new UserModel();
	        RoleModel role = new RoleModel();
	        role.setRoleName(roles.get(0));
	        user.setUsername(userDetail.getUsername());

	        user.setRoles(role);

	        String issuer = request.getRequestURL().toString();

	        Map<String, String> tokens = JwtUtils.buildTokens(user, issuer);

	        response.setContentType("application/json");

	        new ObjectMapper().writeValue(response.getOutputStream(), tokens);

	    }
}
