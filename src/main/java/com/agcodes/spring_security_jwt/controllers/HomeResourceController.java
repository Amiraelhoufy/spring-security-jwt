package com.agcodes.spring_security_jwt.controllers;

import com.agcodes.spring_security_jwt.jwt.JwtUtil;
import com.agcodes.spring_security_jwt.models.AuthenticationRequest;
import com.agcodes.spring_security_jwt.models.AuthenticationResponse;
import com.agcodes.spring_security_jwt.services.AppUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class HomeResourceController {
  @Autowired
  private AuthenticationManager authenticationManager;
  @Autowired
  private AppUserDetailsService appUserDetailsService;

  @Autowired
  private JwtUtil jwtUtil;

  @RequestMapping("/hello")
  @ResponseBody
  public String hello() {
    return "Hello World!";
  }

  @PostMapping("/authenticate")
  public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) throws Exception{

    // 1. Authenticate Username & Password
    try{
      authenticationManager.authenticate(
          new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(),authenticationRequest.getPassword()));
    }catch (BadCredentialsException e){
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Incorrect Username or Password!");
    }

    // 2. return the userDetail by username
    final UserDetails userDetails = appUserDetailsService.loadUserByUsername(
        authenticationRequest.getUsername());

    // 3. use JWT to generate a jwt Token
    final String jwt = jwtUtil.generateToken(userDetails);

    // 4. return authentication Response with the jwt
    return ResponseEntity.ok(new AuthenticationResponse(jwt));
  }




}
