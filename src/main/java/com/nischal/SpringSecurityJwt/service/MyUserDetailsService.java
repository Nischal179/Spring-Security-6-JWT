package com.nischal.SpringSecurityJwt.service;

import com.nischal.SpringSecurityJwt.model.UserPrincipal;
import com.nischal.SpringSecurityJwt.model.Users;
import com.nischal.SpringSecurityJwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class MyUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Users users = userRepository.findByUsername(username);

        if(users == null) {
            System.out.println("User Not Found");
            throw new UsernameNotFoundException("User not found");
        }
//  DaoAuthenticationProvider expects a UserDetails object to represent
//  the authenticated user, and UserPrincipal meets this requirement.
        return new UserPrincipal(users);
    }
}
