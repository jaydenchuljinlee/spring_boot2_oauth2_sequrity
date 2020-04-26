package com.community.web.resolver;

import com.community.web.annotation.SocialUser;
import com.community.web.domain.User;
import com.community.web.domain.enums.SocialType;
import com.community.web.repository.UserRepository;
import org.springframework.core.MethodParameter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import javax.servlet.http.HttpSession;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Component
public class UserArgumentResolver implements HandlerMethodArgumentResolver {
    private final UserRepository userRepository;

    public UserArgumentResolver(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public boolean supportsParameter(MethodParameter parameter) {//어떤것을 적용할지 지정
        return (parameter.getParameterAnnotation(SocialUser.class) != null) &&
                parameter.getParameterType().equals(User.class);
    }

    @Override
    public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer, NativeWebRequest webRequest, WebDataBinderFactory binderFactory) throws Exception {
        HttpSession session = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest().getSession();

        User user = (User) session.getAttribute("user");

        return  getUser(user, session);
    }

    private User getUser(User user, HttpSession session) {
        if (user != null) {
            return user;
        }

        OAuth2AuthenticationToken auth2AuthenticationToken =
                (OAuth2AuthenticationToken) SecurityContextHolder.getContext().getAuthentication();

        Map<String, Object> attributes = auth2AuthenticationToken.getPrincipal().getAttributes();

        User convertUser = convertUser(auth2AuthenticationToken.getAuthorizedClientRegistrationId(), attributes);

        user = userRepository.findByEmail(convertUser.getEmail())
                .orElse(userRepository.save(convertUser));

        setRoleIfNotSame(user, auth2AuthenticationToken, attributes);
        session.setAttribute("user",user);

        return user;
    }

    private User convertUser(String authority, Map<String, Object> attributes) {
        if (SocialType.FACEBOOK.isEuqals(authority)) {
            return getModernUser(SocialType.FACEBOOK,attributes);
        } else if (SocialType.GOOGLE.isEuqals(authority)) {
            return getModernUser(SocialType.GOOGLE,attributes);
        } else if (SocialType.KAKAO.isEuqals(authority)) {
            return getKakaoUser(attributes);
        }
        return null;
    }

    private User getModernUser(SocialType socialType, Map<String, Object> attributes) {
        return User.builder()
                .name(String.valueOf(attributes.get("name")))
                .email(String.valueOf(attributes.get("email")))
                .principal(String.valueOf(attributes.get("id")))
                .socialType(socialType)
                .createdDate(LocalDateTime.now())
                .build();

    }

    private User getKakaoUser(Map<String, Object> attributes) {
        Map<String, String> propertiesMap =
                (HashMap<String, String>) attributes.get("properties");

        String email = String.valueOf(attributes.get("id")) + "@community.com";

                return User.builder()
                        .name(propertiesMap.get("nickName"))
                        //.email(String.valueOf(attributes.get("kaccount_email")))
                        .email(email)
                        .principal(String.valueOf(attributes.get("id")))
                        .socialType(SocialType.KAKAO)
                        .createdDate(LocalDateTime.now())
                        .build();
    }


    private void setRoleIfNotSame(User user, OAuth2AuthenticationToken auth2AuthenticationToken, Map<String, Object> attributes) {
        if (auth2AuthenticationToken.getAuthorities().contains(new SimpleGrantedAuthority(user.getSocialType().getRoleType()))) {

            SecurityContextHolder.getContext().setAuthentication(
                    new UsernamePasswordAuthenticationToken(attributes, "N/A",
                            AuthorityUtils.createAuthorityList(user.getSocialType().getRoleType()))
            );
        }
    }

}
