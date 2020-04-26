package com.community.web.Controller;

import com.community.web.annotation.SocialUser;
import com.community.web.domain.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpSession;

@Slf4j
@Controller
public class LoginController {

    @GetMapping("/login")
    public String login() {

        //HttpSession session = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest().getSession();

        //log.info(session);

        return "login";
    }

    @GetMapping("/loginSuccess")
    public String loginSuccess(@SocialUser User user) {
        log.info("성공");

        return "login";
    }

    @GetMapping("/loginFailure")
    public String loginFailure() {
        log.info("실패");
        return "login";
    }
}
