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

    @Resource
    private UserClient userClient;

    @Resource
    private JwtService jwtService;
    @Resource
    PasswordEncoder passwordEncoder;


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
        var token = jwtService.generateToken(existUser);

        return AuthResponse.builder()
                .token(token)
                .success(authenticated)
                .build();

    }

}
