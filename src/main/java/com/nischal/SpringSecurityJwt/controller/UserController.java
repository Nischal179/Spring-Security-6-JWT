package com.nischal.SpringSecurityJwt.controller;

import com.nischal.SpringSecurityJwt.model.Users;
import com.nischal.SpringSecurityJwt.service.UserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    @Autowired
    private UserService service;

    @PostMapping("/register")
    public Users register(@RequestBody Users users) {
        return service.register(users);
    }

    @PostMapping("/login")
    public ResponseEntity<Void> login(@RequestBody Users users, HttpServletResponse response) {
        String jwt = service.verify(users);

        if (!"Fail".equals(jwt)) {

            //Create an HTTP-only cookie for the JWT
            Cookie jwtCookie = new Cookie("token",jwt);
            jwtCookie.setHttpOnly(true);
            jwtCookie.setSecure(false);
            jwtCookie.setPath("/");
            jwtCookie.setMaxAge(60);

            // Add the cookie to the response
            response.addCookie(jwtCookie);

            // Return a response with 200 OK status
            return ResponseEntity.ok().build();
        }

        // Return a 401 Unauthorized status if authentication fails
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
}
