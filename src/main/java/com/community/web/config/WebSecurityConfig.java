package com.community.web.config;

import com.community.web.domain.enums.SocialType;
import com.community.web.oauth.CustomOAuth2Provider;
import com.community.web.provider.CustomAuthenticationProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.web.filter.CharacterEncodingFilter;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

@Slf4j
@EnableWebSecurity // 웹시큐리티 사용하겠다는 어노테이션
@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private CustomAuthenticationProvider authenticationProvider;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(authenticationProvider);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        CharacterEncodingFilter filter = new CharacterEncodingFilter();

        http.authorizeRequests()
                .antMatchers("/","/oauth/**","/oauth2/callback","/oauth/token", "/oauth2/**", "/login/**","/css/**", "/images/**", "/js/**", "/console/**","/swagger-ui.html")
                    .permitAll()
                .antMatchers("/facebook")
                    .hasAnyAuthority(SocialType.FACEBOOK.getRoleType())
                .antMatchers("/google")
                    .hasAnyAuthority(SocialType.GOOGLE.getRoleType())
                .antMatchers("/kakao")
                    .hasAnyAuthority(SocialType.KAKAO.getRoleType())
                .anyRequest()
                    .authenticated()
            //.and()
                //.oauth2Login()
                  //  .defaultSuccessUrl("/loginSuccess")
                   // .failureUrl("/loginFailure")
            .and()
                .headers()
                    .frameOptions().disable()
            .and()
                .formLogin()
            /*.and()
                .exceptionHandling()
                    .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
            .and()
                .formLogin()
                    .successForwardUrl("/loginSuccess")
            .and()
                .logout()
                    .logoutUrl("/logout")
                    .logoutSuccessUrl("/")
                    .deleteCookies("JSESSIONID")
                    .invalidateHttpSession(true)*/
            .and()
                .addFilterBefore(filter, CsrfFilter.class)
                .csrf().disable().httpBasic();
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository(OAuth2ClientProperties oAuth2ClientProperties,
                                                                     @Value("${custom.oauth2.kakao.client-id}") String kakaoClientId,
                                                                     @Value("${custom.oauth2.kakao.client-secret}") String kakaoClientSecret) {
        List<ClientRegistration> registrationList =
                oAuth2ClientProperties.getRegistration().keySet().stream()
                .map(client -> getRegistration(oAuth2ClientProperties, client))
                .filter(Objects::nonNull)
                .collect(Collectors.toList());


        registrationList.add(CustomOAuth2Provider.KAKAO.getBuilder("kakao")
            .clientId(kakaoClientId)
            .clientSecret(kakaoClientSecret)
            .jwkSetUri("test")
            .build());

        log.info(registrationList.size()+"");

        return new InMemoryClientRegistrationRepository(registrationList);
    }

    private ClientRegistration getRegistration(OAuth2ClientProperties oAuth2ClientProperties, String client) {
        if ("google".equals(client)) {
            OAuth2ClientProperties.Registration registration =
                    oAuth2ClientProperties.getRegistration().get("google");

            return CommonOAuth2Provider.GOOGLE.getBuilder(client)
                    .clientId(registration.getClientId())
                    .clientSecret(registration.getClientSecret())
                    .scope("email", "profile")
                    .build();
        }

        if ("facebook".equals(client)) {
            OAuth2ClientProperties.Registration registration =
                    oAuth2ClientProperties.getRegistration().get("facebook");



            return CommonOAuth2Provider.FACEBOOK.getBuilder(client)
                    .clientId(registration.getClientId())
                    .clientSecret(registration.getClientSecret())
                    // 페북의 graph API는 scope로는 필요한 필드를 반환해주지 않아 idm name, email, link를 파라미터로 넣어 요청하도록 설정
                    .userInfoUri("https://graph.facebook.com/me?fields=id,name,email,link")
                    .scope("email")
                    .build();
        }

        return null;
    }
}
