package com.nischal.SpringSecurityJwt.filterPackage;

import com.nischal.SpringSecurityJwt.service.JWTService;
import com.nischal.SpringSecurityJwt.service.MyUserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtFilter.class);

    @Autowired
    private JWTService jwtService;

    @Autowired
    MyUserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // Get access token and refresh token from cookies
        String accessToken = getTokenFromCookies(request, "access_token");
        String refreshToken = getTokenFromCookies(request, "refresh_token");;
        String username = null;

        logger.info("Access Token: "+accessToken);
        logger.info("Refresh Token: "+ refreshToken);

        if (accessToken != null ) {
            // Check if the access token is expired
            if (jwtService.isTokenExpired(accessToken)) {
                logger.info("Access token expired.");
                // Access token is expired, check if refresh token is valid
                if (refreshToken != null && jwtService.validateRefreshToken(jwtService.extractUserName(accessToken), refreshToken)) {
                    logger.info("Refresh token is valid. Generating new access token.");
                    // Generate new access token using the refresh token
                    username = jwtService.extractUserName(accessToken);
                    String newAccessToken = jwtService.generateToken(username);
                    logger.info("New Access Token: " + newAccessToken);

                    // Update the access token cookie
                    Cookie newAccessTokenCookie = new Cookie("access_token", newAccessToken);
                    newAccessTokenCookie.setHttpOnly(true);
                    newAccessTokenCookie.setSecure(true);
                    newAccessTokenCookie.setPath("/");
                    newAccessTokenCookie.setMaxAge(60 * 15); // 15 minutes
                    response.addCookie(newAccessTokenCookie);

                    // Set authentication with new token
                    UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                    setAuthentication(userDetails, request);
                } else {
                    logger.warn("Invalid or expired refresh token.");
                }
            } else {
                logger.info("Access token is still valid.");

                // Access token is valid, proceed to extract the username
                username = jwtService.extractUserName(accessToken);
                if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                    if (jwtService.validateToken(accessToken, userDetails)) {
                            // Set authentication with valid token
                            setAuthentication(userDetails, request);
                    }
                }
            }
        }

        filterChain.doFilter(request,response);
    }


    private String getTokenFromCookies(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(name)) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    private void setAuthentication(UserDetails userDetails, HttpServletRequest request) {
        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(userDetails,null, userDetails.getAuthorities());
        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authToken);
    }
}
