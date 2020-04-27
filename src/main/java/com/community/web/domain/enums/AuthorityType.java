package com.community.web.domain.enums;

import lombok.Getter;

@Getter
public enum AuthorityType {

    USER("user"),ADMIN("admin");

    private String role;

    AuthorityType(String role) {
        this.role = role;
    }
}
