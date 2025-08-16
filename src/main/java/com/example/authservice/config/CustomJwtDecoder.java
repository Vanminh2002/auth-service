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
//import java.nio.file.Files;
//import java.nio.file.Path;
//import java.security.KeyFactory;
//import java.security.interfaces.RSAPublicKey;
//import java.security.spec.X509EncodedKeySpec;
//import java.util.Base64;
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
//        String keyStr = Files.readString(Path.of("keys/public.pem"));
//        RSAPublicKey publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA")
//                .generatePublic(new X509EncodedKeySpec(Base64.getDecoder()
//                        .decode(keyStr.replaceAll("-----\\w+ PUBLIC KEY-----", "").replaceAll("\\s", ""))));
//        return NimbusJwtDecoder.withPublicKey(publicKey).build();
//    }
//}
