package ir.sayar.authentication_server.mongotokenstore;

import com.mongodb.client.result.DeleteResult;
import eu.bitwalker.useragentutils.OperatingSystem;
import eu.bitwalker.useragentutils.UserAgent;
import ir.sayar.authentication_server.mongotokenstore.model.OauthAccessToken;
import ir.sayar.authentication_server.mongotokenstore.model.OauthRefreshToken;
import ir.sayar.authentication_server.util.Print;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.mobile.device.Device;
import org.springframework.mobile.device.DeviceUtils;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.util.SerializationUtils;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.DefaultAuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * @author Meghdad Hajilo
 */
public class MongoTokenStore implements TokenStore {

    private static final Log LOG = LogFactory.getLog(MongoTokenStore.class);

    private Query selectAccessTokenCriteria(String extractTokenKey) {
        Query query = new Query();
        query.addCriteria(Criteria.where(OauthAccessToken.FN.token_id.toString()).is(extractTokenKey));
        query.fields()
                .include(OauthAccessToken.FN.token_id.toString())
                .include(OauthAccessToken.FN.token.toString());
        return query;
    }

    private Query selectAccessTokenAuthenticationCriteria(String extractTokenKey) {
        Query query = new Query();
        query.addCriteria(Criteria.where(OauthAccessToken.FN.token_id.toString()).is(extractTokenKey));
        query.fields()
                .include(OauthAccessToken.FN.token_id.toString())
                .include(OauthAccessToken.FN.authentication.toString());
        return query;
    }

    private Query selectAccessTokenFromAuthenticationCriteria(String key) {
        return Query.query(Criteria.where(OauthAccessToken.FN.token_id.toString()).is(key));

    }

    private Query selectAccessTokensFromUserNameAndClientIdCriteria(String userName, String clientId) {
        Query query = new Query();
        query.addCriteria(
                new Criteria().andOperator(
                        Criteria.where(OauthAccessToken.FN.user_name.toString()).is(userName),
                        Criteria.where(OauthAccessToken.FN.client_id.toString()).is(clientId)
                )
        );
        query.fields()
                .include(OauthAccessToken.FN.token_id.toString())
                .include(OauthAccessToken.FN.token.toString());
        return query;
    }

    private Query selectAccessTokensFromUserNameCriteria(String userName) {
        Query query = new Query();
        query.addCriteria(Criteria.where(OauthAccessToken.FN.user_name.toString()).is(userName));
        query.fields()
                .include(OauthAccessToken.FN.token_id.toString())
                .include(OauthAccessToken.FN.token.toString());
        return query;

    }

    private Query selectAccessTokensFromClientIdCriteria(String clientId) {
        Query query = new Query();
        query.addCriteria(Criteria.where(OauthAccessToken.FN.token_id.toString()).is(clientId));
        query.fields()
                .include(OauthAccessToken.FN.token_id.toString())
                .include(OauthAccessToken.FN.token.toString());
        return query;

    }

    private Query deleteAccessTokenCriteria(String extractTokenKey) {
        return Query.query(Criteria.where(OauthAccessToken.FN.token_id.toString()).is(extractTokenKey));
    }

    private Query selectRefreshTokenCriteria(String extractTokenKey) {
        Query query = new Query();
        query.addCriteria(Criteria.where(OauthRefreshToken.FN.token_id.toString()).is(extractTokenKey));
        query.fields()
                .include(OauthRefreshToken.FN.token_id.toString())
                .include(OauthRefreshToken.FN.token.toString());
        return query;
    }

    private Query selectRefreshTokenAuthenticationCriteria(String extractTokenKey) {
        Query query = new Query();
        query.addCriteria(Criteria.where(OauthRefreshToken.FN.token_id.toString()).is(extractTokenKey));
        query.fields()
                .include(OauthRefreshToken.FN.token_id.toString())
                .include(OauthRefreshToken.FN.authentication.toString());
        return query;
    }

    private Query deleteRefreshTokenCriteria(String extractTokenKey) {
        return Query.query(Criteria.where(OauthRefreshToken.FN.token_id.toString()).is(extractTokenKey));
    }

    private Query deleteAccessTokenFromRefreshTokenCriteria(String extractTokenKey) {
        return Query.query(Criteria.where(OauthAccessToken.FN.refresh_token.toString()).is(extractTokenKey));

    }

    private AuthenticationKeyGenerator authenticationKeyGenerator = new DefaultAuthenticationKeyGenerator();

    private JwtAccessTokenConverter jwtTokenEnhancer;


    /**
     * Create a JwtTokenStore with this token enhancer (should be shared with the DefaultTokenServices if used).
     *
     * @param jwtTokenEnhancer
     */
    public MongoTokenStore(JwtAccessTokenConverter jwtTokenEnhancer) {
        this.jwtTokenEnhancer = jwtTokenEnhancer;
    }

    @Autowired
    private MongoTemplate mongoTemplate;

    public void setAuthenticationKeyGenerator(AuthenticationKeyGenerator authenticationKeyGenerator) {
        this.authenticationKeyGenerator = authenticationKeyGenerator;
    }

    @Override
    public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
        System.out.println("OAuth2AccessToken");

        OAuth2AccessToken accessToken = null;

        String key = authenticationKeyGenerator.extractKey(authentication);

        OauthAccessToken oauthAccessToken = mongoTemplate.findOne(
                selectAccessTokenFromAuthenticationCriteria(key),
                OauthAccessToken.class);

        if (oauthAccessToken == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Failed to find access token for authentication " + authentication);
            }
        } else {
            try {
                accessToken = deserializeAccessToken(oauthAccessToken.getToken());
            } catch (IllegalArgumentException e) {
                LOG.error("Could not extract access token for authentication " + authentication, e);
            }
        }

        if (accessToken != null
                && !key.equals(authenticationKeyGenerator.extractKey(readAuthentication(accessToken.getValue())))) {
            removeAccessToken(accessToken.getValue());
            // Keep the store consistent (maybe the same user is represented by this
            // authentication but the details have changed)
            storeAccessToken(accessToken, authentication);
        }
        return accessToken;
    }

    @Override
    public void storeAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
        System.out.println("storeAccessToken");
        String refreshToken = null;

        if (token.getRefreshToken() != null) {
            refreshToken = token.getRefreshToken().getValue();
        }

        if (readAccessToken(token.getValue()) != null) {
            removeAccessToken(token.getValue());
        }

        OauthAccessToken oauthAccessToken = new OauthAccessToken();
        oauthAccessToken.setToken_id(extractTokenKey(token.getValue()));
        oauthAccessToken.setToken(serializeAccessToken(token));
        oauthAccessToken.setAuthentication_id(authenticationKeyGenerator.extractKey(authentication));
        oauthAccessToken.setUser_name(authentication.isClientOnly() ? null : authentication.getName());
        oauthAccessToken.setClient_id(authentication.getOAuth2Request().getClientId());
        oauthAccessToken.setAuthentication(serializeAuthentication(authentication));
        oauthAccessToken.setRefresh_token(extractTokenKey(refreshToken));
        oauthAccessToken.setUserAgent(UserAgent.parseUserAgentString(
                ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes())
                        .getRequest().getHeader("User-Agent")));
        mongoTemplate.save(oauthAccessToken);
    }

    @Override
    public OAuth2AccessToken readAccessToken(String tokenValue) {
        System.out.println("readAccessToken");

        OauthAccessToken oauthAccessToken = mongoTemplate.findOne(
                selectAccessTokenCriteria(extractTokenKey(tokenValue)),
                OauthAccessToken.class);

        if (oauthAccessToken == null) {
            if (LOG.isInfoEnabled()) {
                LOG.info("Failed to find access token for token " + tokenValue);
            }
        } else {
            try {
                return deserializeAccessToken(oauthAccessToken.getToken());
            } catch (IllegalArgumentException e) {
                LOG.warn("Failed to deserialize access token for " + tokenValue, e);
                removeAccessToken(tokenValue);
            }
        }
        return null;
    }

    @Override
    public void removeAccessToken(OAuth2AccessToken token) {
        System.out.println("removeAccessToken");
        removeAccessToken(token.getValue());
    }

    public void removeAccessToken(String tokenValue) {
        mongoTemplate.remove(deleteAccessTokenCriteria(extractTokenKey(tokenValue)), OauthAccessToken.class);
    }

    @Override
    public OAuth2Authentication readAuthentication(OAuth2AccessToken token) {
        return readAuthentication(token.getValue());
    }

    @Override
    public OAuth2Authentication readAuthentication(String token) {

        OauthAccessToken oauthAccessToken = mongoTemplate.findOne(
                selectAccessTokenAuthenticationCriteria(extractTokenKey(token)),
                OauthAccessToken.class);

        if (oauthAccessToken == null) {
            LOG.info("Failed to find access token for token " + token);
        } else {
            try {
                return deserializeAuthentication(oauthAccessToken.getAuthentication());
            } catch (IllegalArgumentException e) {
                LOG.warn("Failed to deserialize authentication for " + token, e);
                removeAccessToken(token);
            }
        }
        return null;
    }

    @Override
    public void storeRefreshToken(OAuth2RefreshToken refreshToken, OAuth2Authentication authentication) {
        System.out.println("storeRefreshToken");
        OauthRefreshToken oauthRefreshToken = new OauthRefreshToken();
        oauthRefreshToken.setToken_id(extractTokenKey(refreshToken.getValue()));
        oauthRefreshToken.setToken(serializeRefreshToken(refreshToken));
        oauthRefreshToken.setAuthentication(serializeAuthentication(authentication));
        oauthRefreshToken.setUserAgent(UserAgent.parseUserAgentString(
                ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes())
                        .getRequest().getHeader("User-Agent")));
        mongoTemplate.save(oauthRefreshToken);
    }

    @Override
    public OAuth2RefreshToken readRefreshToken(String token) {
        System.out.println("readRefreshToken");

        OauthRefreshToken oauthRefreshToken = mongoTemplate.findOne(
                selectRefreshTokenCriteria(extractTokenKey(token)),
                OauthRefreshToken.class);


        if (oauthRefreshToken == null) {
            if (LOG.isInfoEnabled()) {
                LOG.info("Failed to find refresh token for token " + token);
            }
        } else {
            try {
                return deserializeRefreshToken(oauthRefreshToken.getToken());
            } catch (IllegalArgumentException e) {
                LOG.warn("Failed to deserialize refresh token for token " + token, e);
                removeRefreshToken(token);
            }
        }

        return null;
    }

    @Override
    public void removeRefreshToken(OAuth2RefreshToken token) {
        System.out.println("removeRefreshToken");
        removeRefreshToken(token.getValue());
    }

    public void removeRefreshToken(String token) {
        DeleteResult deleteResult = mongoTemplate.remove(
                deleteRefreshTokenCriteria(extractTokenKey(token)), OauthRefreshToken.class);
        if (deleteResult.getDeletedCount() == 0) {
            LOG.info("Failed to delete refresh token for OauthRefreshToken " + extractTokenKey(token));
        } else
            LOG.info("Successfully delete refresh token for OauthRefreshToken " + extractTokenKey(token));
    }

    @Override
    public OAuth2Authentication readAuthenticationForRefreshToken(OAuth2RefreshToken token) {
        System.out.println("readAuthenticationForRefreshToken");
        return readAuthenticationForRefreshToken(token.getValue());
    }

    public OAuth2Authentication readAuthenticationForRefreshToken(String value) {

        OauthRefreshToken oauthRefreshToken = mongoTemplate.findOne(
                selectRefreshTokenAuthenticationCriteria(extractTokenKey(value)),
                OauthRefreshToken.class);

        if (oauthRefreshToken == null) {
            LOG.info("Failed to find access token for token " + value);
        } else {
            try {
                return deserializeAuthentication(oauthRefreshToken.getAuthentication());
            } catch (IllegalArgumentException e) {
                LOG.warn("Failed to deserialize access token for " + value, e);
                removeAccessToken(value);
            }
        }
        return null;
    }

    @Override
    public void removeAccessTokenUsingRefreshToken(OAuth2RefreshToken refreshToken) {
        System.out.println("removeAccessTokenUsingRefreshToken");
        removeAccessTokenUsingRefreshToken(refreshToken.getValue());

    }

    public void removeAccessTokenUsingRefreshToken(String refreshToken) {

        DeleteResult deleteResult = mongoTemplate.remove(
                deleteAccessTokenFromRefreshTokenCriteria(extractTokenKey(refreshToken)),
                OauthAccessToken.class);

        if (deleteResult.getDeletedCount() == 0) {
            LOG.info("Failed to delete access token for refreshToken " + refreshToken);
        } else
            LOG.info("Successfully delete access token for refreshToken " + refreshToken);
    }

    @Override
    public Collection<OAuth2AccessToken> findTokensByClientId(String clientId) {
        System.out.println("findTokensByClientId");
        List<OAuth2AccessToken> accessTokens = new ArrayList<OAuth2AccessToken>();

        List<OauthAccessToken> oauthAccessTokenList = mongoTemplate.find(
                selectAccessTokensFromClientIdCriteria(clientId), OauthAccessToken.class);

        if (oauthAccessTokenList == null || oauthAccessTokenList.isEmpty()) {
            if (LOG.isInfoEnabled()) {
                LOG.info("Failed to find access token for clientId " + clientId);
            }
        }
        accessTokens = safeAccessTokenRowMapper(oauthAccessTokenList);

        return accessTokens;
    }

    private List<OAuth2AccessToken> safeAccessTokenRowMapper(List<OauthAccessToken> accessTokens) {
        List<OAuth2AccessToken> list = new ArrayList<OAuth2AccessToken>();

        for (OauthAccessToken oauthAccessToken : accessTokens) {

            try {
                list.add(deserializeAccessToken(oauthAccessToken.getToken()));
            } catch (IllegalArgumentException e) {
                mongoTemplate.remove(deleteAccessTokenCriteria(oauthAccessToken.getToken_id()), OauthAccessToken.class);
            }
        }

        return list;
    }

    public Collection<OAuth2AccessToken> findTokensByUserName(String userName) {
        List<OAuth2AccessToken> accessTokens = new ArrayList<OAuth2AccessToken>();

        List<OauthAccessToken> oauthAccessTokenList = mongoTemplate.find(
                selectAccessTokensFromUserNameCriteria(userName), OauthAccessToken.class);

        if (oauthAccessTokenList == null || oauthAccessTokenList.isEmpty())
            if (LOG.isInfoEnabled())
                LOG.info("Failed to find access token for userName " + userName);

        accessTokens = safeAccessTokenRowMapper(oauthAccessTokenList);

        return accessTokens;
    }

    @Override
    public Collection<OAuth2AccessToken> findTokensByClientIdAndUserName(String clientId, String userName) {
        System.out.println("findTokensByClientIdAndUserName");
        List<OAuth2AccessToken> accessTokens = new ArrayList<OAuth2AccessToken>();

        List<OauthAccessToken> oauthAccessTokenList = mongoTemplate.find(
                selectAccessTokensFromUserNameAndClientIdCriteria(userName, clientId),
                OauthAccessToken.class);

        if (oauthAccessTokenList == null || oauthAccessTokenList.isEmpty()) {
            if (LOG.isInfoEnabled()) {
                LOG.info("Failed to find access token for clientId " + clientId + " and userName " + userName);
            }
        }

        accessTokens = safeAccessTokenRowMapper(oauthAccessTokenList);

        return accessTokens;
    }

    protected String extractTokenKey(String value) {
        if (value == null) {
            return null;
        }
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("MD5 algorithm not available.  Fatal (should be in the JDK).");
        }

        try {
            byte[] bytes = digest.digest(value.getBytes("UTF-8"));
            return String.format("%032x", new BigInteger(1, bytes));
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("UTF-8 encoding not available.  Fatal (should be in the JDK).");
        }
    }

    protected byte[] serializeAccessToken(OAuth2AccessToken token) {
        return SerializationUtils.serialize(token);
    }

    protected OAuth2AccessToken deserializeAccessToken(byte[] token) {
        return SerializationUtils.deserialize(token);
    }

    protected byte[] serializeRefreshToken(OAuth2RefreshToken token) {
        return SerializationUtils.serialize(token);
    }

    protected OAuth2RefreshToken deserializeRefreshToken(byte[] token) {
        return SerializationUtils.deserialize(token);
    }

    protected byte[] serializeAuthentication(OAuth2Authentication authentication) {
        return SerializationUtils.serialize(authentication);
    }

    protected OAuth2Authentication deserializeAuthentication(byte[] authentication) {
        return SerializationUtils.deserialize(authentication);
    }

}
