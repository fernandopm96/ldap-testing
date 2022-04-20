package com.crysec.ldapprueba.services;

import com.crysec.ldapprueba.models.User;
import org.springframework.stereotype.Service;

@Service
public class UserService {
    public User loadUserByUsername(String username){
        User user = new User();
        user.setUsername(username);
        user.setId(1L);
        return user;

    }
}
