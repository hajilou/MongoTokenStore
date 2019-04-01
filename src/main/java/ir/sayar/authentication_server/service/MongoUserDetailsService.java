package ir.sayar.authentication_server.service;

import ir.sayar.authentication_server.model.MongoUser;
import ir.sayar.authentication_server.util.Print;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.*;


/**
 * @author Meghdad Hajilo
 */

@Service
public class MongoUserDetailsService implements UserDetailsService {
    @Autowired
    private MongoTemplate mongoTemplate;


    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();

//        for(String s:this.roles){
//            GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("ROLE_" + s);
            GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("ROLE_USER");
            grantedAuthorities.add(grantedAuthority);
//        }
        return grantedAuthorities;
    }

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        MongoUser user = mongoTemplate.findOne(
                Query.query(Criteria.where("username").is(username)),
                MongoUser.class);

//        user=new MongoUser(null,"admin", passwordEncoder.encode("admin"),
//                new HashSet<String>(Arrays.asList("ROLE_USER")),
//                true, true,
//                true, true);
//        mongoTemplate.save(user);
        if (user == null) {
            throw new UsernameNotFoundException(
                    String.format("Username %s not found", username));
        }

        String[] roles = new String[user.getAuthorities().size()];
        return user;
//		return new User(user.getUsername(), user.getPassword(),
//				AuthorityUtils.createAuthorityList(user.getRoles().toArray(roles)));
    }
}
