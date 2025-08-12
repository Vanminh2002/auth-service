package com.example.authservice.dto.request;

import lombok.Data;

@Data
public class LogoutRequest {
    private String token;
}
