package ir.sayar.authentication_server.endpoint;

import eu.bitwalker.useragentutils.UserAgent;
import ir.sayar.authentication_server.exception.BadRequestException;
import ir.sayar.authentication_server.model.MongoUser;
import ir.sayar.authentication_server.model.SignInRequest;
import ir.sayar.authentication_server.util.Print;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.mongodb.core.MongoOperations;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.http.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpoint;
import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpClientErrorException.BadRequest;
import org.springframework.web.client.RestTemplate;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.util.Arrays;

/**
 * @author Meghdad Hajilo
 */
@FrameworkEndpoint
public class RevokeTokenEndpoint {

    @Resource(name = "tokenServices")
    ConsumerTokenServices tokenServices;

    @RequestMapping(method = RequestMethod.DELETE, value = "/oauth/token")
    @ResponseBody
    public void revokeToken(HttpServletRequest request) {
        String authorization = request.getHeader("Authorization");
        System.out.println(authorization != null);
        System.out.println(authorization.contains("Bearer"));
        if (authorization != null && authorization.contains("Bearer")) {
            String tokenId = authorization.substring("Bearer".length() + 1);
            System.out.println("----");
            System.out.println(tokenServices.revokeToken(tokenId));
            System.out.println("----");
        }
    }

    @Value("${gateway.clientId}")
    String clientId;
    @Value("${gateway.clientSecret}")
    String clientSecret;
    @Value("${server.port}")
    String port;
    @Autowired
    BCryptPasswordEncoder encoder;
    @Autowired
    private MongoOperations operations;

    @PostMapping("login")
    public ResponseEntity<?> signIn(HttpServletRequest request,@RequestBody @Valid SignInRequest signInRequest) {

        UserAgent userAgent = UserAgent.parseUserAgentString(request.getHeader("User-Agent"));
        Print.print(userAgent);

        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
        headers.setBasicAuth(clientId, clientSecret);
        HttpEntity entity = new HttpEntity(headers);

        String url = String.format(
                "http://localhost:%s/spring-security-oauth-server/oauth/token" +
                        "?grant_type=password&username=%s&password=%s",
                port, signInRequest.getUsername(), signInRequest.getPassword());

        Print.print(restTemplate.exchange(url, HttpMethod.POST, entity, Object.class));
        Print.print(url);
        Print.print(entity);
        return restTemplate.exchange(url, HttpMethod.POST, entity, Object.class);
    }

    @PostMapping("signup")
    public ResponseEntity<?> signup(@RequestBody @Valid SignInRequest signInRequest) throws BadRequest {
        if(operations.exists(Query.query(Criteria.where("username").is(signInRequest.getUsername())),MongoUser.class)) {
            throw new BadRequestException("Username is exist. Please enter other username.");
        }
        MongoUser mongoUser = new MongoUser();
        mongoUser.setUsername(signInRequest.getUsername());
        mongoUser.setPassword(encoder.encode(signInRequest.getPassword()));
        mongoUser.getRoles().add("ROLE_USER");
        operations.save(mongoUser);
        return ResponseEntity.created(null).build();
    }

    @GetMapping(value = "/oauth/revoke-token")
    @ResponseStatus(HttpStatus.OK)
    public void logout(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null) {
            String tokenValue = authHeader.replace("Bearer", "").trim();
//            OAuth2AccessToken accessToken = tokenStore.readAccessToken(tokenValue);
//            tokenStore.removeAccessToken(accessToken);
            tokenServices.revokeToken(tokenValue);
        }
    }
}