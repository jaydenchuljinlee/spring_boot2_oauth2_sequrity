package com.community.web.Controller;

import com.community.web.domain.OAuthToken;
import com.google.gson.Gson;
import lombok.RequiredArgsConstructor;
import org.apache.commons.codec.binary.Base64;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;


@RequiredArgsConstructor
@RestController
@RequestMapping("/login/oauth2")
public class Oauth2Controller {

    private final Gson gson;
    private final RestTemplate restTemplate;

    @GetMapping("/code")
    public OAuthToken redirectSocial(@RequestParam String code) throws Exception {

        String credentials = "testClientId:testSecret";
        String encodedCredentials = new String(Base64.encodeBase64(credentials.getBytes()));

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.add("Athorization","Basic" + encodedCredentials);

        MultiValueMap<String,String> params = new LinkedMultiValueMap<>();
        params.add("code",code);
        params.add("grant_type","authorization_code");
        params.add("redirect_uri","http://localhost:8080/login/oauth2/code");

        HttpEntity<MultiValueMap<String,String>> request = new HttpEntity<>(params,headers);

        ResponseEntity<String> response = restTemplate.postForEntity("http://localhost:8080/oauth/token",request,String.class);

        if (response.getStatusCode() == HttpStatus.OK) {
            return gson.fromJson(response.getBody(), OAuthToken.class);
        }

        return null;


    }
}
