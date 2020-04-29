package com.community.web.domain;

import com.community.web.domain.enums.SocialType;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.persistence.*;
import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;


@Builder
@NoArgsConstructor @AllArgsConstructor
@Entity @Getter
public class User implements UserDetails {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_no")
    private Long userNo;

    @Column(name = "name")
    private String name;
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @Column(name = "password")
    private String password;
    @Column(name = "email")
    private String email;

    @Column(name = "created_date")
    private LocalDateTime createdDate;
    @Column(name = "updated_date")
    private LocalDateTime updatedDate;

    @Column(name = "address_1")
    private String address1;
    @Column(name = "address_2")
    private String address2;
    @Column(name = "address_3")
    private String address3;
    @Column(name = "phone")
    private String phone;
    @Column(name = "mileage")
    private int mileage;
    @Column(name = "status")
    private int status;
    @Column(name = "grade")
    private int grade;
    @Column(name = "auth")
    private String auth;

    // OAuth
    @Column(name = "principal")
    private String principal;
    @Column(name = "social_type")
    private SocialType socialType;

    //권한 리스트
    @Transient
    List<? extends GrantedAuthority> authorities;

    public void setAuthorities(List<? extends GrantedAuthority> authorities) {this.authorities = authorities;}

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @Override
    public String getUsername() {
        return this.email;
    }

    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @Override
    public boolean isEnabled() {
        return true;
    }
}
