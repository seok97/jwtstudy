package com.cos.jwtstudy.config;

import com.cos.jwtstudy.config.jwt.JwtAuthorizationFilter;
import com.cos.jwtstudy.filter.MyFilter3;
import com.cos.jwtstudy.config.jwt.JwtAuthenticationFilter;
import com.cos.jwtstudy.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsFilter corsFilter;

    @Autowired
    private CorsConfig corsConfig;

    @Autowired
    private UserRepository userRepository;

    @Bean
    public BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf().disable();
//        http.addFilterAfter(new MyFilter3(), SecurityContextPersistenceFilter.class);
        /**
         * 기본적으로 웹은 stateless 인데 statefull 로 사용하기 위해 세션과 쿠키를 사용한다.
         * 이와 같은 방식을 사용하지 않는 것을 sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) 로 설정 한다.
         */
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(corsFilter) // cors 설정 필터, @CrossOrigin(인증 X), 시큐리티 필터에 등록 인증
                .formLogin().disable()
                .httpBasic().disable()
                .apply(new MyCustomDsl())
                .and()
                .authorizeRequests()
                .antMatchers("/api/v1/user/**")
                .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/manager/**")
                .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/admin/**")
                .access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll();
        return http.build();
    }

    /**
     * WebSecurityConfigurerAdapter deprecated 이슈
     * 위 security 세팅에 아래와 같이 WebSecurityConfigurerAdapter 의 authenticationManager 를 인자로 필터에 추가 해주면 되었으나
     * HttpSecurity.addFilter(new JwtAuthenticationFilter(authenticationManager()))
     *
     * authenticationManager 를 아래 내부클래스로 작성하여 추가하였다.
     * .apply(new MyCustomDsl())
     */
    public class MyCustomDsl extends AbstractHttpConfigurer<MyCustomDsl, HttpSecurity> {
        @Override
        public void configure(HttpSecurity http) throws Exception {
            AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
            http
                    .addFilter(corsConfig.corsFilter())
                    .addFilter(new JwtAuthenticationFilter(authenticationManager))
                    .addFilter(new JwtAuthorizationFilter(authenticationManager, userRepository));
        }
    }
}
