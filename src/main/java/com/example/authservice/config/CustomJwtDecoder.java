//package com.example.authservice.config;
//
//import com.example.authservice.service.AuthService;
//import jakarta.annotation.Resource;
//import lombok.experimental.NonFinal;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.security.oauth2.jwt.Jwt;
//import org.springframework.security.oauth2.jwt.JwtDecoder;
//import org.springframework.security.oauth2.jwt.JwtException;
//import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
//
//public class CustomJwtDecoder implements JwtDecoder {
//
//
//    @NonFinal
//    @Value("${jwt.signerKey}")
//    protected String SECRET_KEY;
//
//    @Resource
//    private AuthService authService;
//
//    @Resource
//    private NimbusJwtDecoder nimbusJwtDecoder;
//
//    @Override
//    public Jwt decode(String token) throws JwtException {
//       try  {
//           var response = authService.
//       }
//    }
//}
