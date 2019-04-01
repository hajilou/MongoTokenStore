package ir.sayar.authentication_server.model;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.*;

/**
 * @author Meghdad Hajilo
 */
@Document(collection = "user")
public class MongoUser implements UserDetails {

    @Id
    private String id;

    private String username;
    private String password;
    private Set<String> roles;

    private boolean  isAccountNonExpired;
    private boolean  isAccountNonLocked;
    private boolean  isCredentialsNonExpired;
    private boolean  isEnabled;

    public MongoUser() {
        this.roles=new HashSet<>();
        this.isAccountNonExpired=true;
        this.isAccountNonLocked=true;
        this.isCredentialsNonExpired=true;
        this.isEnabled=true;
    }

    public MongoUser(String id, String username, String password, Set<String> roles, boolean isAccountNonExpired, boolean isAccountNonLocked, boolean isCredentialsNonExpired, boolean isEnabled) {
        this.id = id;
        this.username = username;
        this.password = password;
        this.roles = roles;
        this.isAccountNonExpired = isAccountNonExpired;
        this.isAccountNonLocked = isAccountNonLocked;
        this.isCredentialsNonExpired = isCredentialsNonExpired;
        this.isEnabled = isEnabled;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return this.isAccountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return this.isAccountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return this.isCredentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return this.isEnabled;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();

        for(String s:this.roles){
//            GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("ROLE_" + s);
            GrantedAuthority grantedAuthority = new SimpleGrantedAuthority(s);
            grantedAuthorities.add(grantedAuthority);
        }
        return grantedAuthorities;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Set<String> getRoles() {
        return roles;
    }

    public void setRoles(Set<String> roles) {
        this.roles = roles;
    }
}