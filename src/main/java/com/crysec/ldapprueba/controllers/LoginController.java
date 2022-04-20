package com.crysec.ldapprueba.controllers;

import com.crysec.ldapprueba.dto.JwtRequest;
import com.crysec.ldapprueba.dto.JwtResponse;
import com.crysec.ldapprueba.models.User;
import com.crysec.ldapprueba.security.utils.JwtTokenUtil;
import com.crysec.ldapprueba.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/login")
public class LoginController {

    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtTokenUtil jwtTokenUtil;
    @Autowired
    private UserService userService;

    @PostMapping
    public ResponseEntity<?> createAuthenticationToken(@RequestBody JwtRequest authenticationRequest) throws Exception {
        authenticate(authenticationRequest.getUsername(), authenticationRequest.getPassword());
        final User userDetails = userService.loadUserByUsername(authenticationRequest.getUsername());
        final String token = jwtTokenUtil.generateToken(userDetails);
        return ResponseEntity.ok(new JwtResponse(token));
    }

    private void authenticate(String username, String password) throws Exception {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        } catch (DisabledException e) {
            throw new Exception("USER_DISABLED", e);
        } catch (BadCredentialsException e){
            throw new Exception("INVALID_CREDENTIALS", e);
        }
    }
}
