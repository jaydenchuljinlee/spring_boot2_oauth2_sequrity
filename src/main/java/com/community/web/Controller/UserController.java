package com.community.web.Controller;

import com.community.web.domain.User;
import com.community.web.repository.UserRepository;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@Api(tags = {"1. User"})
@RequiredArgsConstructor
@RestController
@RequestMapping("/v1")
public class UserController {

    private final UserRepository userRepository;

    @ApiOperation(value = "회원 조회", notes = "모든 회원 조회")
    @GetMapping("/users")
    public List<User> findAllUser() {

        return userRepository.findAll();
    }
}
