package com.nischal.SpringSecurityJwt.service;

import com.nischal.SpringSecurityJwt.model.Users;
import com.nischal.SpringSecurityJwt.repository.UserRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    private JWTService jwtService;

    private BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);

    public Users register(Users users) {
        users.setPassword(encoder.encode(users.getPassword()));
        return (userRepository.save(users));

    }

    public void verify(Users users, HttpServletResponse response) {
        Authentication authentication =
                authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(users.getUsername(),
                        users.getPassword()));

        if (authentication.isAuthenticated()) {
            String accessToken = jwtService.generateToken(users.getUsername());
            String refreshToken = jwtService.generateRefreshToken(users.getUsername());

            addCookiesToResponse(response, accessToken, refreshToken);
        }

    }

    private void addCookiesToResponse(HttpServletResponse response, String accessToken, String refreshToken) {
        Cookie accessTokenCookie = new Cookie("access_token", accessToken);
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setSecure(true); // Set this to true if using HTTPS
        accessTokenCookie.setPath("/");
        accessTokenCookie.setMaxAge(10*60); // 15 minute

        Cookie refreshTokenCookie = new Cookie("refresh_token", refreshToken);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(true); // Set this to true if using HTTPS
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setMaxAge(7 * 24 * 60 * 60); // 7 days

        response.addCookie(accessTokenCookie);
        response.addCookie(refreshTokenCookie);
    }

    public void logout(HttpServletResponse response) {
        Cookie accessTokenCookie = new Cookie("access_token", null);
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setSecure(true); // Set this to true if using HTTPS
        accessTokenCookie.setPath("/");
        accessTokenCookie.setMaxAge(0); // Delete the cookie

        Cookie refreshTokenCookie = new Cookie("refresh_token", null);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(true); // Set this to true if using HTTPS
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setMaxAge(0); // Delete the cookie

        response.addCookie(accessTokenCookie);
        response.addCookie(refreshTokenCookie);
    }

    public String extractTokenFromCookies(HttpServletRequest request, String tokenName) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(tokenName)) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    public boolean validateRefreshToken(String refreshToken) {
        Users user = userRepository.findByRefreshToken(refreshToken);
        return user != null && !jwtService.isTokenExpired(user.getExpiryDate());
    }

    public String generateNewAccessTokenFromRefreshToken(String refreshToken) {
        Users user = userRepository.findByRefreshToken(refreshToken);
        if (user != null) {
            return jwtService.generateToken(user.getUsername());
        }
        return null;
    }
}
