package br.gov.sp.iamspe.configserver.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    private Environment env;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
        .authorizeRequests()
            .antMatchers("/encrypt", "/encrypt.html").hasRole("ADMIN")
            .antMatchers("/decrypt", "/dencrypt.html").hasRole("ADMIN")
            .anyRequest().authenticated()
        .and()
            .httpBasic()
        .and()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
            .withUser("admin").password("{noop}" + env.getProperty("app.users.admin.password")).roles("ADMIN")
            .and()
            .withUser("client").password("{noop}" + env.getProperty("app.users.client.password")).roles("USER");
    }
    
}
