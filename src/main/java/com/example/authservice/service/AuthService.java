package com.example.authservice.service;

//
//import com.example.authservice.client.permission.PermissionClient;
//import com.example.authservice.client.role.RoleClient;
import com.example.authservice.client.user.UserClient;
import com.example.authservice.dto.permission.PermissionDto;
import com.example.authservice.dto.request.AuthRequest;
import com.example.authservice.dto.response.AuthResponse;
import com.example.authservice.dto.role.RoleDto;
import com.example.authservice.dto.user.UserDto;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import jakarta.annotation.Resource;
import lombok.experimental.NonFinal;
import lombok.extern.slf4j.Slf4j;
import org.example.dto.ApiResponse;
import org.example.exception.AppException;
import org.example.exception.ErrorCode;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import javax.management.relation.Role;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;


@Slf4j
@Service
public class AuthService {

    @NonFinal
    @Value("${jwt.signerKey}")
    protected String SECRET_KEY;


    @Resource
    private UserClient userClient;
    @Resource
    PasswordEncoder passwordEncoder;

//    @Resource
//    private RoleClient roleClient;
//    @Resource
//    private PermissionClient permissionClient;

    public AuthResponse login(AuthRequest request) {
        List<UserDto> user = userClient.getAllUsers().getData();

        UserDto existUser = user
                .stream()
                .filter(userDto -> userDto.getUsername().equals(request.getUsername()))
                .findFirst()
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_FOUND));


        boolean authenticated = passwordEncoder.matches(request.getPassword(), existUser.getPassword());


        if (!authenticated) {
            throw new AppException(ErrorCode.UNAUTHENTICATED);
        }
        var token = generalToken(existUser);

        return AuthResponse.builder()
                .token(token)
                .success(authenticated)
                .build();

    }


    private String generalToken(UserDto user) {
        JWSHeader header = new JWSHeader(JWSAlgorithm.HS512);

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject(user.getUsername())
                .issuer(user.getUsername())
                .issueTime(new Date())
                .expirationTime(new Date(Instant.now()
                        .plus(15, ChronoUnit.MINUTES)
                        .toEpochMilli()))
                .jwtID(UUID.randomUUID().toString())
                .claim("scope", buildScope(user))
                .build();

        Payload payload = new Payload(jwtClaimsSet.toJSONObject());

        JWSObject jwsObject = new JWSObject(header, payload);

        try {
            jwsObject.sign(new MACSigner(SECRET_KEY.getBytes()));
            return jwsObject.serialize();
        } catch (KeyLengthException e) {
            throw new RuntimeException(e);
        } catch (JOSEException e) {
            log.error("Can not create token", e);
            throw new RuntimeException(e);
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
                        .flatMap(r -> r.getPermissions().stream()
                                .map(PermissionDto::getName))
                        .filter(Objects::nonNull)
                        .forEach(scopeJoiner::add);
            }
        }
        return scopeJoiner.toString();
    }
}
