package com.agcodes.spring_security_jwt.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
public class JwtUtil {

  @Value("${jwt.secret}")
  private String secret;

  private SecretKey key;

  // Load and initialize the key once
  @PostConstruct
  public void init() {
    try{
    byte[] decodedKey = Base64.getDecoder().decode(secret);
    if (decodedKey.length < 32) {
      throw new IllegalArgumentException("Secret key must be at least 32 bytes long for HS256");
    }
    this.key = Keys.hmacShaKeyFor(decodedKey);
  } catch(IllegalArgumentException e) {
    throw new RuntimeException("Invalid JWT secret key provided.", e);
  }

}

  public String extractUsername(String token) {
    return extractClaim(token, Claims::getSubject);
  }

  public Date extractExpiration(String token) {
    return extractClaim(token, Claims::getExpiration);
  }

  public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
    final Claims claims = extractAllClaims(token);
    return claimsResolver.apply(claims);
  }
  private Claims extractAllClaims(String token) {
//    return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
    return Jwts.parserBuilder()
        .setSigningKey(key)  // Use the SecretKey here
        .build()
        .parseClaimsJws(token)
        .getBody();
  }

  private Boolean isTokenExpired(String token) {
    return extractExpiration(token).before(new Date());
  }

  public String generateToken(UserDetails userDetails) {

    Map<String, Object> claims = new HashMap<>();
    return createToken(claims, userDetails.getUsername());

  }

  private String createToken(Map<String, Object> claims, String subject) {

//    Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256); // Generate a secure key

    return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
        .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
        .signWith(key, SignatureAlgorithm.HS256).compact();
  }

  public Boolean validateToken(String token, UserDetails userDetails) {
    final String username = extractUsername(token);
    return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
  }
}