package com.community.web.domain.enums;

import lombok.Getter;

@Getter
public enum AuthorityType {

    USER(0,"user"),ADMIN(1,"admin");

    private int order;
    private String type;

    AuthorityType(int order,String type) {
        this.order = order;
        this.type = type;
    }

    public String getType() {return this.type.toUpperCase();}
}
