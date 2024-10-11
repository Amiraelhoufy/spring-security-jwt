package com.agcodes.spring_security_jwt;

import com.agcodes.spring_security_jwt.filters.JwtRequestFilter;
import com.agcodes.spring_security_jwt.services.AppUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {
  @Autowired
  JwtRequestFilter jwtRequestFilter;
  @Autowired
  private AppUserDetailsService userDetailsService;

  @Autowired
  public void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.userDetailsService(userDetailsService);

  }

  @Bean
  public PasswordEncoder passwordEncoder(){
    return NoOpPasswordEncoder.getInstance();
  }

  // Expose AuthenticationManager bean
  //  define an AuthenticationManager bean using AuthenticationConfiguration.
  //  This allows you to autowire the AuthenticationManager in your controller as before.
  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
    return config.getAuthenticationManager();
  }

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{

    // Authorize any request and make sure it's fully authenticated
     http
         .csrf((csrf)-> csrf.disable())
         .authorizeRequests(
                authorize->authorize
                    .requestMatchers("/authenticate").permitAll()
                    .anyRequest().authenticated()
         )
         .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
         .addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class); // Add JWT filter;

    return http.build();

  }


}
