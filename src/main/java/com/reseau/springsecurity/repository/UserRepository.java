package com.reseau.springsecurity.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.reseau.springsecurity.model.UserModel;

public interface UserRepository extends JpaRepository<UserModel,Long>{
	UserModel findByUsername(String username);
}
