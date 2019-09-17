package be.technocite.jwtrest.config;

import be.technocite.jwtrest.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static be.technocite.jwtrest.model.Role.ADMIN;
import static be.technocite.jwtrest.model.Role.USER;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        UserDetailsService userDetailsService = userDetails();
        auth.userDetailsService(userDetailsService)
                .passwordEncoder(bCryptPasswordEncoder());
    }

    @Override
    protected void configure(HttpSecurity security) throws Exception {
        //désactive l'authentification basique du protocole HTTP
        security.httpBasic().disable()

                //on désactive la sécurité qui empêche un pirate de faire des requêtes depuis son ordinateur
                //inconnu du système
                .csrf().disable()

                //l'architecture REST ne doit pas sauvegarder de session, sans état => STATELESS
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and().authorizeRequests()

                //autoriser toutes les requêtes de tout le monde sur /login et /register
                .antMatchers("/api/auth/login").permitAll()
                .antMatchers("/api/auth/register").permitAll()

                //autorise toutes les requêtes d'utilisteurs avec les roles soit ADMIN soit USER pour les requêtes GET
                //sur les URI enfants de /api/products
                .antMatchers(HttpMethod.GET, "/api/products/**").hasAnyAuthority(ADMIN.toString(), USER.toString())

                //on autorise seulement l'ADMIN à pouvoir rajouter des produits
                .antMatchers(HttpMethod.POST, "/api/products/**").hasAuthority(ADMIN.toString())

                //on définit la réponse lorsque le client n'est pas authorisé
                .and().exceptionHandling().authenticationEntryPoint(unauthorizedEntryPoint())

                //on ajoute le filtre
                .and().addFilterBefore(new JwtTokenFilter(jwtTokenProvider), UsernamePasswordAuthenticationFilter.class);

    }

    /*on définit la réponse lorsque le client n'est pas authorisé*/
    @Bean
    public AuthenticationEntryPoint unauthorizedEntryPoint() {
        return new AuthenticationEntryPoint() {
            @Override
            public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
            }
        };
//        return ((request, response, authException) -> response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized"));
    }

    @Bean
    public PasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetails() {
        return new UserService();
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
