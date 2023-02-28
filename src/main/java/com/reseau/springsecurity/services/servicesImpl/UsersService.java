package com.reseau.springsecurity.services.servicesImpl;

import java.util.ArrayList;
import java.util.Collection;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.reseau.springsecurity.model.UserModel;
import com.reseau.springsecurity.repository.UserRepository;

@Service
public class UsersService implements UserDetailsService {

	@Autowired
	UserRepository usersRepository;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		// TODO Auto-generated method stub
		 UserModel user = usersRepository.findByUsername(username);

	        try {
	            Collection<SimpleGrantedAuthority> authority = new ArrayList<>();

	            authority.add(new SimpleGrantedAuthority(user.getRoles().getRoleName()));

	            return new User(user.getUsername(),user.getPassword(), authority);
	        }
	        catch(Exception e) {
	            return null;
	        }
	}

}
