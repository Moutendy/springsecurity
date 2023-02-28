package com.reseau.springsecurity.model;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "USERS")
public class UserModel {
	
	    @Id
	    @GeneratedValue(strategy = GenerationType.IDENTITY)
	    private Long id;

	    @Column(name="USERNAME" ,nullable = false, updatable = true)
	    private String username;
    
	    @Column(name="PASSWORD" ,nullable = false, updatable = true)
        private String password;
	    
	    @ManyToOne(fetch = FetchType.EAGER)
	    @JoinColumn(name = "ROLE_ID" ,nullable = true, updatable = true)
	    private RoleModel roles;
}
