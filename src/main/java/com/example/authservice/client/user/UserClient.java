package com.example.authservice.client.user;

import com.example.authservice.dto.permission.PermissionDto;
import com.example.authservice.dto.role.RoleDto;
import com.example.authservice.dto.user.UserDto;
import org.example.dto.ApiResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import java.util.List;

@FeignClient(name = "user-service",url = "http://localhost:8081")
public interface UserClient {
    @GetMapping("/users/get-all")
    ApiResponse<List<UserDto>> getAllUsers();

    @GetMapping("/permission/get-by/{id}")
    ApiResponse<PermissionDto> getByPermissionId(@PathVariable("id") List<Long> id);


    @GetMapping("/roles/get-by/{id}")
    ApiResponse<List<RoleDto>> getRoleById(@PathVariable("id") List<Long> id);
}
