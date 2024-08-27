package com.nischal.SpringSecurityJwt.filterPackage;

import com.nischal.SpringSecurityJwt.service.JWTService;
import com.nischal.SpringSecurityJwt.service.MyUserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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

    @Autowired
    private JWTService jwtService;

    @Autowired
    MyUserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // Get access token and refresh token from cookies
        String accessToken = getTokenFromCookies(request, "accessToken");
        String refreshToken = null;
        String username = null;

        if (accessToken != null ) {
            username = jwtService.extractUserName(accessToken);
        }

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            if (jwtService.validateToken(accessToken, userDetails)) {
                setAuthentication(userDetails, request);

            } else if ("/refreshToken".equals(request.getRequestURI())) {
                // Get refresh token only if the request path matches "/refresh-token"
                refreshToken = getTokenFromCookies(request, "refreshToken");

                if (refreshToken != null && jwtService.validateRefreshToken(username)){
                    // Generate new access token using the refresh token
                    String newAccessToken = jwtService.generateToken(username);
                    Cookie newAccessTokenCookie = new Cookie("accessToken", newAccessToken);
                    newAccessTokenCookie.setHttpOnly(true);
                    newAccessTokenCookie.setSecure(true); // Ensure to use secure flag in production
                    newAccessTokenCookie.setPath("/");
                    newAccessTokenCookie.setMaxAge(60 * 15); // 15 minutes or your desired expiration time
                    response.addCookie(newAccessTokenCookie);

                    setAuthentication(userDetails, request);
                } else {
                    // Refresh token is also invalid, prompt login
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Please log in again.");
                    return;
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
