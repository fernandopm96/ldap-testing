package com.crysec.ldapprueba.services;

import com.crysec.ldapprueba.models.User;

public class JwtUserDetailsService {
    public User loadUserByUsername(String username){
        User user = new User();
        user.setUsername(username);
        user.setId(1L);
        return user;
    }
}
