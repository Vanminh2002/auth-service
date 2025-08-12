package com.example.authservice.dto.role;

import com.example.authservice.dto.permission.PermissionDto;
import com.example.authservice.dto.user.UserDto;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class RoleDto {
    private Long id;
    private String name;
    private String description;
    List<PermissionDto> permissions;

}
