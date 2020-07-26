# 스프링부트2를 통한 oauth2 클라이언트와 리소스 서버 구현 

- 스프링 부트의 2.x 버전에서 OAuth 2.0을 통해 클라이언트와 리소스 서버를 구현해본 프로젝트입니다.
- 데이터베이스로는 MySql을 사용하였으며, 데이터베이스 툴은 HeidiSQL을 사용했습니다.

# 클라이언트 주요 소스

## [WebSecurityConfig.java]
- 시큐리티 관련 설정입니다.

```java

@Slf4j
@Order(2)
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
	    .and()
		.oauth2Login()
		  .defaultSuccessUrl("/loginSuccess")
		  .failureUrl("/loginFailure")
	    .and()
		.headers()
		    .frameOptions().disable()
	    .and()
		.formLogin()
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

    //카카오 관련 클라이언트 설정.
    @Bean
    public ClientRegistrationRepository clientRegistrationRepository(OAuth2ClientProperties oAuth2ClientProperties,
                                                                     @Value("${custom.oauth2.kakao.client-id}") String kakaoClientId) {
        List<ClientRegistration> registrationList =
                oAuth2ClientProperties.getRegistration().keySet().stream()
                .map(client -> getRegistration(oAuth2ClientProperties, client))
                .filter(Objects::nonNull)
                .collect(Collectors.toList());


        registrationList.add(CustomOAuth2Provider.KAKAO.getBuilder("kakao")
            .clientId(kakaoClientId)
            .jwkSetUri("test")
            .build());

        log.info(registrationList.size()+"");

        return new InMemoryClientRegistrationRepository(registrationList);
    }

    //구글 관련 클라이언트 설정.
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
```

## [CustomAuthenticationProvider.java]
- 카카오,구글,페이스북 등의 정보를 제공하는 공통 provider custom

```java

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
```

## [UserArgumentResolver.java]
- 연동 로그인이 성공했을 때, 로그인 정보를 제공할 resolver

```java

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
```

## [SocialUser.java]
- 로그인 성공시 UserArgumentResolver로 넘겨줄 annotaion

```java

@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
public @interface SocialUser {

}
```

## [LoginController.java]
- 로그인 관련 컨트롤러

```java

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
```

# 인증 및 자원 서버 관련 설정

## [Oauth2AuthorizationConfig.java]
- 인증 서버 관련 소스
- oauth 요청이 들어왔을 때, 토큰 정보를 어떤 방식으로 확인하고 전달할지 설정하는 부분

```java
/**
 * id/password 기반 Oauth2 인증을 담당하는 서버
 * 다음 endpont가 자동 생성 된다.
 * /oauth/authorize
 * /oauth/token
 */
@Slf4j
@RequiredArgsConstructor
@Configuration
@EnableAuthorizationServer
public class Oauth2AuthorizationConfig extends AuthorizationServerConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;
    private final DataSource dataSource;
    private final CustomUserDetailService customUserDetailService;

    //공개키 기반의 방식을 사용함을 설정
    @Value("${spring.security.oauth2.jwt.signkey}")
    private String signkey;

    //JWT 토큰을 사용함을 설정
    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();

        converter.setSigningKey(signkey);
        return converter;
    }

    //시큐리티 설정
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) {
        security.tokenKeyAccess("permitAll()")
                .checkTokenAccess("isAuthenticated()") //allow check token
                .allowFormAuthenticationForClients();
    }

    /**
     * 클라이언트 정보 주입 방식을 jdbcdetail로 변경
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.jdbc(dataSource).passwordEncoder(passwordEncoder);
    }

    //사용자 인증을 처리할 endpoint 
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        super.configure(endpoints);

        endpoints.accessTokenConverter(jwtAccessTokenConverter()).userDetailsService(customUserDetailService);
    }
}
```

## [Oauth2ResourceServerConfig.java]
- 자원 서버 관련 소스
- 인증 서버에서 요청이 들어오면, 접근 권한을 확인하여 결과를 반환하는 역할

```java
@Configuration
@EnableResourceServer
public class Oauth2ResourceServerConfig extends ResourceServerConfigurerAdapter {

    @Override
    public void configure(HttpSecurity http) throws Exception {
       http.headers().frameOptions().disable();
       http.authorizeRequests()
               .antMatchers("/v1/users").access("#oauth2.hasAnyScope('read')")
                .anyRequest().authenticated();
    }
}
```

## [Oauth2Controller.java]
- 인증 서버에게 자신을 검증하기 위한 컨트롤러
- 인증 서버로부터 코드값을 받으면, 클라이언트 정보를 Base64로 인코딩하고 oauth 구조에 맞게 변환한 후 return 

```java
@Slf4j
@RequiredArgsConstructor
@RestController
@RequestMapping("/oauth2")
public class Oauth2Controller {

    private final Gson gson;
    private final RestTemplate restTemplate;

    @GetMapping("/callback")
    public OAuthToken redirectSocial(@RequestParam String code) throws Exception {

        String credentials = "testClientId:testSecret";
        String encodedCredentials = new String(Base64.encodeBase64(credentials.getBytes()));
        
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.add("Authorization", "Basic " + encodedCredentials);
        
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("code", code);
        params.add("grant_type", "authorization_code");
        params.add("redirect_uri", "https://localhost:8443/oauth2/callback");
        
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
        
        ResponseEntity<String> response = restTemplate.postForEntity("http://localhost:8081/oauth/token", request, String.class);
        
        if (response.getStatusCode() == HttpStatus.OK) {
            return gson.fromJson(response.getBody(), OAuthToken.class);
        }

        return null;
    }

    @GetMapping(value = "/token/refresh")
    public OAuthToken refreshToken(@RequestParam String refreshToken) throws Exception {

        String credentials = "testClientId:testSecret";
        String encodedCredentials = new String(Base64.encodeBase64(credentials.getBytes()));

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.add("Authorization", "Basic " + encodedCredentials);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();

        params.add("refresh_token", refreshToken);
        params.add("grant_type", "refresh_token");
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

        ResponseEntity<String> response = restTemplate.postForEntity("http://localhost:8081/oauth/token", request, String.class);

        if (response.getStatusCode() == HttpStatus.OK) {
            return gson.fromJson(response.getBody(), OAuthToken.class);
        }
        return null;
    }
}
```

# DB 관련 테이블 설정입니다.

## [user 테이블] 
- 프로젝트에서 사용한 사용자 테이블입니다.
```sql
CREATE TABLE `user` (
	`user_no` INT(11) NOT NULL AUTO_INCREMENT,
	`identity` VARCHAR(255) NULL DEFAULT NULL COLLATE 'utf8mb4_general_ci',
	`password` VARCHAR(255) NULL DEFAULT NULL COLLATE 'utf8mb4_general_ci',
	`name` VARCHAR(50) NULL DEFAULT NULL COLLATE 'utf8mb4_general_ci',
	`created_date` DATETIME NULL DEFAULT NULL,
	`email` VARCHAR(255) NULL DEFAULT NULL COLLATE 'utf8mb4_general_ci',
	`principal` VARCHAR(255) NULL DEFAULT NULL COLLATE 'utf8mb4_general_ci',
	`social_type` VARCHAR(50) NULL DEFAULT NULL COLLATE 'utf8mb4_general_ci',
	`address_1` VARCHAR(50) NULL DEFAULT NULL COLLATE 'utf8mb4_general_ci',
	`address_2` VARCHAR(255) NULL DEFAULT NULL COLLATE 'utf8mb4_general_ci',
	`address_3` VARCHAR(255) NULL DEFAULT NULL COLLATE 'utf8mb4_general_ci',
	`phone` VARCHAR(255) NULL DEFAULT NULL COLLATE 'utf8mb4_general_ci',
	`updated_date` DATETIME NULL DEFAULT NULL,
	`mileage` INT(7) NULL DEFAULT NULL,
	`status` INT(11) NULL DEFAULT NULL,
	`grade` INT(11) NULL DEFAULT NULL,
	`auth` VARCHAR(50) NULL DEFAULT NULL COLLATE 'utf8mb4_general_ci',
	PRIMARY KEY (`user_no`) USING BTREE
)
COLLATE='utf8mb4_general_ci'
ENGINE=InnoDB
AUTO_INCREMENT=17
;

```

## [oauth_client_details] 
 - /ouath2/authorize?~ 로 인증 요청을 보낼 때, DB에 저장되어 있는 클라이언트 정보를 확인하기 위한 테이블

```sql
CREATE TABLE `oauth_client_details` (
	`client_id` VARCHAR(256) NOT NULL COLLATE 'utf8_general_ci',
	`resource_ids` VARCHAR(256) NULL DEFAULT NULL COLLATE 'utf8_general_ci',
	`client_secret` VARCHAR(256) NULL DEFAULT NULL COLLATE 'utf8_general_ci',
	`scope` VARCHAR(256) NULL DEFAULT NULL COLLATE 'utf8_general_ci',
	`authorized_grant_types` VARCHAR(256) NULL DEFAULT NULL COLLATE 'utf8_general_ci',
	`web_server_redirect_uri` VARCHAR(256) NULL DEFAULT NULL COLLATE 'utf8_general_ci',
	`authorities` VARCHAR(256) NULL DEFAULT NULL COLLATE 'utf8_general_ci',
	`access_token_validity` INT(11) NULL DEFAULT NULL,
	`refresh_token_validity` INT(11) NULL DEFAULT NULL,
	`additional_information` VARCHAR(4096) NULL DEFAULT NULL COLLATE 'utf8_general_ci',
	`autoapprove` VARCHAR(256) NULL DEFAULT NULL COLLATE 'utf8_general_ci',
	PRIMARY KEY (`client_id`) USING BTREE
)
COLLATE='utf8_general_ci'
ENGINE=InnoDB
;

```

## 아래부터는 JWT 토큰을 이용하지 않고 bear 방식을 통해 oauth 인증을 할 때, 서버를 재시작 하게되면 정보가 refresh 되기 때문에 관련 정보를 DB로 관리해주기 위한 테이블 입니다.

## [oauth_access_token]

```sql
CREATE TABLE `oauth_access_token` (
	`token_id` VARCHAR(256) NULL DEFAULT NULL COLLATE 'utf8_general_ci',
	`token` VARBINARY(256) NULL DEFAULT NULL,
	`authentication_id` VARCHAR(256) NOT NULL COLLATE 'utf8_general_ci',
	`user_name` VARCHAR(256) NULL DEFAULT NULL COLLATE 'utf8_general_ci',
	`client_id` VARCHAR(256) NULL DEFAULT NULL COLLATE 'utf8_general_ci',
	`authentication` VARCHAR(256) NULL DEFAULT NULL COLLATE 'utf8_general_ci',
	`refresh_token` VARCHAR(256) NULL DEFAULT NULL COLLATE 'utf8_general_ci',
	PRIMARY KEY (`authentication_id`) USING BTREE
)
COLLATE='utf8_general_ci'
ENGINE=InnoDB
;

```

## [oauth_approvals]

```sql
CREATE TABLE `oauth_approvals` (
	`userId` VARCHAR(256) NULL DEFAULT NULL COLLATE 'utf8_general_ci',
	`clientId` VARCHAR(256) NULL DEFAULT NULL COLLATE 'utf8_general_ci',
	`scope` VARCHAR(256) NULL DEFAULT NULL COLLATE 'utf8_general_ci',
	`status` VARCHAR(10) NULL DEFAULT NULL COLLATE 'utf8_general_ci',
	`expiresAt` TIMESTAMP NULL DEFAULT NULL,
	`lastModifiedAt` TIMESTAMP NULL DEFAULT NULL
)
COLLATE='utf8_general_ci'
ENGINE=InnoDB
;

```

## [oauth_client_token]

```sql
CREATE TABLE `oauth_client_token` (
	`token_id` VARCHAR(256) NULL DEFAULT NULL COLLATE 'utf8_general_ci',
	`token` VARBINARY(256) NULL DEFAULT NULL,
	`authentication_id` VARCHAR(256) NOT NULL COLLATE 'utf8_general_ci',
	`user_name` VARCHAR(256) NULL DEFAULT NULL COLLATE 'utf8_general_ci',
	`client_id` VARCHAR(256) NULL DEFAULT NULL COLLATE 'utf8_general_ci',
	PRIMARY KEY (`authentication_id`) USING BTREE
)
COLLATE='utf8_general_ci'
ENGINE=InnoDB
;

```

## [oauth_code]

```sql
CREATE TABLE `oauth_code` (
	`code` VARCHAR(256) NULL DEFAULT NULL COLLATE 'utf8_general_ci',
	`authentication` VARBINARY(256) NULL DEFAULT NULL
)
COLLATE='utf8_general_ci'
ENGINE=InnoDB
;

```

## [oauth_refresh_token]

```sql
CREATE TABLE `oauth_refresh_token` (
	`token_id` VARCHAR(256) NULL DEFAULT NULL COLLATE 'utf8_general_ci',
	`token` VARBINARY(256) NULL DEFAULT NULL,
	`authentication` VARBINARY(256) NULL DEFAULT NULL
)
COLLATE='utf8_general_ci'
ENGINE=InnoDB
;

```
