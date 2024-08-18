package com.nischal.SpringSecurityJwt.controller;

import com.nischal.SpringSecurityJwt.model.Users;
import com.nischal.SpringSecurityJwt.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
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
}
