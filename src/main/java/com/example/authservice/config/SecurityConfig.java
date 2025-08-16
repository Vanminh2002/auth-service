package com.example.authservice.config;

import lombok.experimental.NonFinal;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Configuration
@EnableWebSecurity
public class SecurityConfig {


    private final String[] PUBLIC_ENDPOINT = {
            "/auth/**",
            "/.well-known/jwks.json"
    };


    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth ->
                                auth.requestMatchers(PUBLIC_ENDPOINT).permitAll()
//                                .requestMatchers(ADMIN_ENDPOINT).hasAnyAuthority("ROLE_ADMIN")
                                        .anyRequest().authenticated()
                );
        http.oauth2ResourceServer(oauth2 ->
                oauth2.jwt(jwt ->
                        {
                            try {
                                jwt.decoder(jwtDecoder())
                                        .jwtAuthenticationConverter(jwtAuthenticationConverter());
                            } catch (Exception e) {
                                throw new RuntimeException(e);
                            }
                        }
                )


        );

        return http.build();
    }


    @Bean
    public JwtDecoder jwtDecoder() throws Exception {
//        String keyStr = Files.readString(Path.of("keys/public.pem"));
//        RSAPublicKey publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA")
//                .generatePublic(new X509EncodedKeySpec(Base64.getDecoder()
//                        .decode(keyStr.replaceAll("-----\\w+ PUBLIC KEY-----", "").replaceAll("\\s", ""))));
//        return NimbusJwtDecoder.withPublicKey(publicKey).build();
        return NimbusJwtDecoder.withJwkSetUri("http://localhost:8000/.well-known/jwks.json").build();
    }


    @Bean
    JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        jwtGrantedAuthoritiesConverter.setAuthorityPrefix("");
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);

        return jwtAuthenticationConverter;
    }


}
