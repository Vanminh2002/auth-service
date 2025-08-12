package com.example.authservice.dto.user;

import lombok.Data;

import java.util.List;

@Data
public class UserDto {
    private String id;
    private String username;
    private String password;
    private List<Long> roleId;

}
