package com.Mohamed.jwtAauthentification.controlleurs;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    @Autowired
    private DataSource dataSource;
    @Value("${spring.queries.users-query}")
    private String usersQuery;
    @Value("${spring.queries.roles-query}")
    private String rolesQuery;

    @Override
    protected void configure(AuthenticationManagerBuilder auth)
            throws Exception {
        auth.
                jdbcAuthentication()
                .usersByUsernameQuery(usersQuery)
                .authoritiesByUsernameQuery(rolesQuery)
                .dataSource(dataSource)
                .passwordEncoder(bCryptPasswordEncoder);
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.
                authorizeRequests()
                .antMatchers("/").permitAll() // accès pour tous
                .antMatchers("/login").permitAll() // accès pour
                .antMatchers("/registration").permitAll() // accès
                .antMatchers("/provider/**").hasAuthority("ADMIN")
                .antMatchers("/article/**").hasAuthority("USER").anyRequest()
                .authenticated().and().csrf().disable().formLogin() // l'accès de
                .loginPage("/login").failureUrl("/login?error=true") // fixer la
                .defaultSuccessUrl("/home") // page d'accueil
                .usernameParameter("email") // paramètres
                .passwordParameter("password")
                .and().logout()
                .logoutRequestMatcher(new
                        AntPathRequestMatcher("/logout")) // route de deconnexion ici
                .logoutSuccessUrl("/login").and().exceptionHandling() // une fois
                .accessDeniedPage("/403");
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web
                .ignoring()
                .antMatchers("/resources/**", "/static/**",
                        "/css/**", "/js/**", "/images/**");
    }
}

