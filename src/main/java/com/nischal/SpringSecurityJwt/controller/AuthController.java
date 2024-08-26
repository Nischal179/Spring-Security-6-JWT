package com.nischal.SpringSecurityJwt.controller;

import com.nischal.SpringSecurityJwt.model.Users;
import com.nischal.SpringSecurityJwt.service.AuthService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {

    @Autowired
    private AuthService authService;

    @PostMapping("/register")
    public Users register(@RequestBody Users users) {
        return service.register(users);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestParam String username, @RequestParam String password,
                                   HttpServletResponse response) {
//        String jwt = service.verify(users);
        authService.loginUser(username, password, response);
        return ResponseEntity.ok("User logged in successfully");
    }
}
