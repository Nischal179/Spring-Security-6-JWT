package com.nischal.SpringSecurityJwt.service;

import com.nischal.SpringSecurityJwt.model.Users;
import com.nischal.SpringSecurityJwt.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.function.Function;

@Service
public class JWTService {

    private static final Logger logger = LoggerFactory.getLogger(JWTService.class);

    @Autowired
    private UserRepository userRepository;

    // Inject the secret key from the application.properties
    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.expiration}")
    private int jwtExpirationInMs;

    @Value("${jwt.refreshExpiration}")
    private int refreshExpirationInMs;

    private BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    // Method to generate access token
    public String generateToken(String username) {
        return generateToken(username, jwtExpirationInMs);
    }

    // Method to generate refresh token
    public String generateRefreshToken(String username) {
        String refreshToken = generateRandomString();
        Date expiryDate = new Date(System.currentTimeMillis() + (2 * 24 * 60 * 60 * 1000)); // 2 days expiry

        Users user = userRepository.findByUsername(username);
        if (user != null) {
            user.setRefreshToken(encoder.encode(refreshToken));
            user.setExpiryDate(expiryDate);
            userRepository.save(user);
        }

        return refreshToken;
    }

    // Method to validate refresh token
    public boolean validateRefreshToken(String username, String refreshToken) {
        logger.info("Validating refresh token for user: " + username);
        Users user = userRepository.findByUsername(username);
        if (user != null) {
            if (isTokenExpired(user.getExpiryDate())) {
                logger.warn("Refresh token for user: " + username + " is expired.");
                return false;
            }

            boolean matches = encoder.matches(refreshToken, user.getRefreshToken());
            if (matches) {
                logger.info("Refresh token is valid.");
                return true;
            } else {
                logger.warn("Refresh token mismatch for user: " + username);
            }
        } else {
            logger.warn("No user found with username: " + username);
        }
        return false;
    }

    // Generate a random string for refresh token
    private String generateRandomString() {
        byte[] randomBytes = new byte[32];
        new Random().nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    // Generic method to generate a token with custom expiration
    public String generateToken(String username, int expirationTimeInMs) {

        logger.info("Generating token for user: " + username);
        Map<String, Object> claims = new HashMap<>();

        // Building the JWT with the claims
        return Jwts.builder()
                .header()
                .add("typ","JWT")
                .and()
                .claims()
                .add(claims)
                .subject(username)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expirationTimeInMs))
                .and()
                .signWith(getKey())
                .compact();
    }

    // Method to sign the JWT for data signature
    private SecretKey getKey() {
        // Using base64 decoder to convert your string to byte
        byte[] keyByte = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyByte);
    }

    public String extractUserName(String token) {
        // extract the username from jwt token
        return extractClaim(token, Claims::getSubject);
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimResolver) {
        final Claims claims = extractAllClaims(token);
        return claimResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public boolean validateToken(String token, UserDetails userDetails) {
        final String userName = extractUserName(token);
        return (userName.equals(userDetails.getUsername()) && !isTokenExpired(token));

    }

    // Check if the JWT token is expired
    public boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // New method to check if a Date object is expired
    public boolean isTokenExpired(Date expiryDate) {
        return expiryDate.before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }
}
