package com.example.authservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class BeanConfiguration {
    //    @Bean
//    public ModelMapper defaultMapper() {
//        ModelMapper m = new ModelMapper();
//        m.getConfiguration()
//                .setCollectionsMergeEnabled(false)
//                .setMatchingStrategy(MatchingStrategies.STRICT);
//        return m;
//    }
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
