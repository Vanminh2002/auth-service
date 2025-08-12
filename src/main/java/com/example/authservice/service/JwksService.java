package com.example.authservice.service;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.stereotype.Service;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;
@Service
public class JwksService {
    public Map<String, Object> getJwks() {
        try {
            RSAPublicKey publicKey = loadPublicKey("keys/public.pem");

            // Tạo RSAKey (JWK) từ public key
            RSAKey jwk = new RSAKey.Builder(publicKey)
                    .keyID("auth-service-key") // kid phải khớp khi ký token
                    .build();

            // Gói vào JWKSet
            JWKSet jwkSet = new JWKSet(jwk);
            return jwkSet.toJSONObject();

        } catch (Exception e) {
            throw new RuntimeException("Cannot load JWKS", e);
        }
    }

    private RSAPublicKey loadPublicKey(String filePath) throws Exception {
        String key = new String(Files.readAllBytes(Paths.get(filePath)));
        key = key.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");

        byte[] decoded = Base64.getDecoder().decode(key);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey pk = kf.generatePublic(spec);
        return (RSAPublicKey) pk;
    }
}
