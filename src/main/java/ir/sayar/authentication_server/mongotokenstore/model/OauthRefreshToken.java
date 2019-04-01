package ir.sayar.authentication_server.mongotokenstore.model;


import eu.bitwalker.useragentutils.UserAgent;
import org.springframework.data.annotation.Transient;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;

/**
 * @author Meghdad Hajilo
 */
public class OauthRefreshToken  {

    @Transient
    public final static String
            ENTITY_NAME = "OauthRefreshToken",
            COLLECTION_NAME = "OauthRefreshToken";

    /**
     * This enum include all field names of parent class
     * to access simply to fields
     * FN abbreviate for Field Name
     */
    public enum FN {
        token_id, token, authentication
    }

    private String token_id;
    private byte[] token;
    private byte[] authentication;
    private UserAgent userAgent;

    public OauthRefreshToken() {
    }

    public String getToken_id() {
        return token_id;
    }

    public void setToken_id(String token_id) {
        this.token_id = token_id;
    }

    public byte[] getToken() {
        return token;
    }

    public void setToken(byte[] token) {
        this.token = token;
    }

    public byte[] getAuthentication() {
        return authentication;
    }

    public void setAuthentication(byte[] authentication) {
        this.authentication = authentication;
    }

    public UserAgent getUserAgent() {
        return userAgent;
    }

    public void setUserAgent(UserAgent userAgent) {
        this.userAgent = userAgent;
    }
}