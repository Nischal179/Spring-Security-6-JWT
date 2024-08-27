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
        return authService.register(users);
    }

//    @PostMapping("/login")
//    public ResponseEntity<String> login(@RequestBody Users users, HttpServletResponse response) {
//        authService.verify(users, response);
//        return ResponseEntity.ok("User logged in successfully");
//    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestParam String username,
                                        @RequestParam String password, HttpServletResponse response) {
        Users users = new Users();
        users.setUsername(username);
        users.setPassword(password);
        authService.verify(users, response);
        return ResponseEntity.ok("User logged in successfully");
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(HttpServletResponse response) {
        authService.logout(response);
        return ResponseEntity.ok("User logged out successfully");
    }

}
