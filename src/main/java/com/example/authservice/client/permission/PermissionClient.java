//package com.example.authservice.client.permission;
//
//import com.example.authservice.dto.permission.PermissionDto;
//import com.example.authservice.dto.user.UserDto;
//import org.example.dto.ApiResponse;
//import org.springframework.cloud.openfeign.FeignClient;
//import org.springframework.web.bind.annotation.GetMapping;
//import org.springframework.web.bind.annotation.PathVariable;
//
//import java.util.List;
//
////@FeignClient(name = "user-service")
//public interface PermissionClient {
//    @GetMapping("/permission/get-by/{id}")
//    ApiResponse<PermissionDto> getByPermissionId(@PathVariable("id") List<Long> id);
//}
