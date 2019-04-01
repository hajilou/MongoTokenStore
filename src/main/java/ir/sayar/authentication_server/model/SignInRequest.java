package ir.sayar.authentication_server.model;

import ir.sayar.authentication_server.constants.PatternList;

import javax.validation.constraints.Pattern;

/**
 * @author Meghdad Hajilo
 */

public class SignInRequest {
    @Pattern(regexp = PatternList.USERNAME,message = "please enter valid character for username")
    private String username;
    @Pattern(regexp = PatternList.password)
    private String password;

    public SignInRequest() {
    }

    public SignInRequest(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
