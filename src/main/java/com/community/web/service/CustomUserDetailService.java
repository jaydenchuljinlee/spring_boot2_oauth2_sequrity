package com.community.web.service;

import com.community.web.domain.User;
import com.community.web.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
@Service
public class CustomUserDetailService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public User loadUserByUsername(String email) {

        log.info("CustomUserDetailService.loadUserByUsername :::");

        log.info(email);

        Optional<User> user = userRepository.findByEmail(email);

        //user 존재 유무
        if (!user.isPresent()) throw new UsernameNotFoundException(email);

        return user.get();
    }
}
