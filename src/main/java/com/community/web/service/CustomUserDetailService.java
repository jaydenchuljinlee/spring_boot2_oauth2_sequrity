package com.community.web.service;

import com.community.web.domain.User;
import com.community.web.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@RequiredArgsConstructor
@Service
public class CustomUserDetailService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public User loadUserByUsername(String email) {

        Optional<User> user = userRepository.findByEmail(email);

        //user 존재 유무
        if (!user.isPresent()) throw new UsernameNotFoundException(email);

        return user.get();
    }
}
