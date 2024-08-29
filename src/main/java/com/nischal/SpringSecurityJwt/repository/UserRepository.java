package com.nischal.SpringSecurityJwt.repository;

import com.nischal.SpringSecurityJwt.model.Users;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<Users, Integer> {
    Users findByUsername(String username);

    Users findByRefreshToken(String refreshToken);
}
