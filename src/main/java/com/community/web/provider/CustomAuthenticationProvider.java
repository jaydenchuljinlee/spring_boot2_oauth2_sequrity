package com.community.web.provider;

import com.community.web.domain.User;
import com.community.web.domain.enums.AuthorityType;
import com.community.web.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Slf4j
@RequiredArgsConstructor
@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;

    @Override
    public Authentication authenticate(Authentication authentication) {

        String email    = authentication.getName();
        String password = authentication.getCredentials().toString();

        User user = userRepository.findByEmail(email).orElseThrow(() ->
                new UsernameNotFoundException("user is not exists")) ;

        if (!passwordEncoder.matches("{noop}"+password,user.getPassword()))
            throw new BadCredentialsException("password is not valid");

        if (user.getAuth() == null)
            throw new AccessDeniedException("Authorization is Nothing");

        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        int cur = AuthorityType.valueOf(user.getAuth()).getOrder();

        for (AuthorityType auth : AuthorityType.values()) {

            if (auth.getOrder() <= cur) {
                authorities.add(new SimpleGrantedAuthority(auth.getType()));
            }
        }

        user.setAuthorities(authorities);

        log.info(user.getAuthorities().toString());

        return new UsernamePasswordAuthenticationToken(email,password,user.getAuthorities());
    }


    @Override
    public boolean supports(Class<?> authentication) {

        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }


}
