//package com.example.authservice.client.role;
//
//import com.example.authservice.dto.role.RoleDto;
//import org.example.dto.ApiResponse;
//import org.springframework.cloud.openfeign.FeignClient;
//import org.springframework.web.bind.annotation.GetMapping;
//import org.springframework.web.bind.annotation.PathVariable;
//
//import java.util.List;
//
////@FeignClient(name = "user-service")
//public interface RoleClient {
//    @GetMapping("/roles/get-by/{id}")
//    ApiResponse<List<RoleDto>> getRoleById(@PathVariable("id") List<Long> id);
//}
