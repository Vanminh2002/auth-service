package com.example.authservice.service;

import com.example.authservice.client.user.UserClient;
import com.example.authservice.dto.permission.PermissionDto;
import com.example.authservice.dto.role.RoleDto;
import com.example.authservice.dto.user.UserDto;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.annotation.Resource;
import org.example.dto.ApiResponse;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Service
public class JwtService {

    private final RSAPrivateKey privateKey;

    @Resource
    private UserClient userClient;

    public JwtService() throws Exception {
        this.privateKey = loadPrivateKey("keys/private.pem");
    }

    private RSAPrivateKey loadPrivateKey(String filePath) throws Exception {
        String key = new String(Files.readAllBytes(Paths.get(filePath)))
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");
        byte[] decoded = Base64.getDecoder().decode(key);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
        return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    public String generateToken(UserDto user) {
        try {
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .keyID("auth-service-key") // trùng với JWKS
                    .type(JOSEObjectType.JWT)
                    .build();

            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .subject(user.getUsername())
                    .issuer("auth-service")
                    .issueTime(new Date())
                    .expirationTime(Date.from(Instant.now().plus(15, ChronoUnit.MINUTES)))
                    .jwtID(UUID.randomUUID().toString())
                    .claim("scope", buildScope(user))
                    .claim("userId", user.getId())
                    .build();

            SignedJWT signedJWT = new SignedJWT(header, claimsSet);
            signedJWT.sign(new RSASSASigner(privateKey));

            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new RuntimeException("Cannot create RSA token", e);
        }


    }

    private String buildScope(UserDto user) {
        StringJoiner scopeJoiner = new StringJoiner(" ");
        if (!CollectionUtils.isEmpty(user.getRoleId())) {
            ApiResponse<List<RoleDto>> role = userClient.getRoleById(user.getRoleId());
            List<RoleDto> roles = role.getData();
            if (roles != null) {
                roles.stream()
                        .filter(r -> r.getPermissions() != null)
                        .forEach(r -> {
                            // Thêm tên role
                            if (r.getName() != null) {
                                scopeJoiner.add(r.getName());
                            }
                            // Thêm từng permission
                            r.getPermissions().stream()
                                    .filter(Objects::nonNull)
                                    .forEach(scopeJoiner::add);
                        });
            }

        }
        return scopeJoiner.toString();
    }
}
