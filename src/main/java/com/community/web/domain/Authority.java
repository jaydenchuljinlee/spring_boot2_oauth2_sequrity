package com.community.web.domain;

import com.community.web.domain.enums.AuthorityType;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;

@Entity
@Getter
@Builder
@RequiredArgsConstructor
@NoArgsConstructor
public class Authority implements GrantedAuthority {

    @OneToMany(mappedBy = "user")
    private User user;

    @Column(name = "auth_name")
    private AuthorityType authName;

    @Override
    public String getAuthority() {
        return "ROLE_" + this.authName;
    }

    public void setUser(User user) {
        this.user = user;
    }
}
