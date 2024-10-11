package com.agcodes.spring_security_jwt.filters;


import com.agcodes.spring_security_jwt.jwt.JwtUtil;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

// Intercepts all the requests and
// Handle the extraction and validation of the JWT token from the request header
@Component
public class JwtRequestFilter extends OncePerRequestFilter{

  @Autowired
  private JwtUtil jwtUtil;

  @Autowired
  private UserDetailsService userDetailsService;
  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {
    // Get the JWT token from the request header
    String authorizationHeader = request.getHeader("Authorization");

    String username = null;
    String jwt = null;

    // Check if the token is present and starts with "Bearer "
    if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
      jwt = authorizationHeader.substring(7); // Extract the token
      try {
        username = jwtUtil.extractUsername(jwt); // Extract username from token
      } catch (ExpiredJwtException e) {
        // Handle token expiration
        throw new IllegalArgumentException("ExpiredJwtException!");
      } catch (Exception e) {
        // Handle other exceptions
        throw new IllegalArgumentException("other Exception occurred!");
      }
    }

    // If username is not null, set the authentication in the security context
    if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
      UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

    if(jwtUtil.validateToken(jwt,userDetails)){
      // set the authentication object
      UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
      authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
      SecurityContextHolder.getContext().setAuthentication(authenticationToken);
    }

    }

    // Continue with the filter chain
    filterChain.doFilter(request, response);
  }
}
