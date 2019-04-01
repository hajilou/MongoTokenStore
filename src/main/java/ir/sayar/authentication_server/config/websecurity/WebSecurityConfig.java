package ir.sayar.authentication_server.config.websecurity;

import ir.sayar.authentication_server.service.MongoUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * @author Meghdad Hajilo
 */
@Configuration
//@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
//@Order(3)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Autowired
    public void globalUserDetails(final AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("john").password(passwordEncoder.encode("123")).roles("USER").and()
                .withUser("tom").password(passwordEncoder.encode("111")).roles("ADMIN").and()
                .withUser("user1").password(passwordEncoder.encode("pass")).roles("USER").and()
                .withUser("admin").password(passwordEncoder.encode("nimda")).roles("ADMIN");
    }


    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        return new MongoUserDetailsService();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService()).passwordEncoder(passwordEncoder());
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {

//        http.csrf().ignoringAntMatchers("/sign-in");
        http.authorizeRequests()
                .antMatchers("/signup").permitAll()
                .antMatchers("/login").permitAll()
                .antMatchers("/oauth/token/revoke").permitAll()
                .antMatchers("/tokens/**").permitAll()
                .antMatchers("/oauth/token/**").permitAll()
                .anyRequest().authenticated()
//                .and().formLogin().permitAll()
//                .and().formLogin().loginPage("http://localhost:8081").permitAll()
                .and().csrf().disable();
    }


    @Override
    public void configure(WebSecurity web) throws Exception {
        super.configure(web);
    }

}
