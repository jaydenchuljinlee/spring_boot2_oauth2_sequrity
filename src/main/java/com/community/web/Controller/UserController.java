package com.community.web.Controller;

import com.community.web.domain.User;
import com.community.web.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RequiredArgsConstructor
@RestController
@RequestMapping("/v1")
public class UserController {

    private final UserRepository userRepository;

    @GetMapping("/users")
    public List<User> findAllUser() {

        return userRepository.findAll();
    }
}
