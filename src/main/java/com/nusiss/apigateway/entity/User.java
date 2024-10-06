package com.nusiss.apigateway.entity;

import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Setter
@Getter
public class User {

    private Integer userId;

    private String username;

    private String email;

    private String password;

    private Role role;

    private LocalDateTime createdAt;

    private LocalDateTime updatedAt;

}

enum Role {
    CUSTOMER, SELLER, ADMIN
}

