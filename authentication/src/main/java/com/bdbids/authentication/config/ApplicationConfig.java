package com.bdbids.authentication.config;

import com.bdbids.authentication.userRepository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

@Configuration
@RequiredArgsConstructor

public class ApplicationConfig {
private final UserRepository userRepo;
@Bean
    public UserDetailsService userDetailsService(){
    return username -> userRepo.findByEmail(username).orElseThrow(()->new UsernameNotFoundException("User not found"));


}
}
