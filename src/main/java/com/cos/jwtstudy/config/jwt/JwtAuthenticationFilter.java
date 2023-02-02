package com.cos.jwtstudy.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwtstudy.auth.PrincipalDetails;
import com.cos.jwtstudy.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter 가 있다.
// /login 요청 에서 username, password 르 전송하면 (post)
// UsernamePasswordAuthenticationFilter 가 동작 한다.
// spring security 설정에서 formlogin을 disable() 하면 동작 하지 않으므로
// spring security 에 필터를 추가해주어야 한다.

@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    // login 요청을 하면 로그인 시도를 위해 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        log.info("JwtAuthenticationFilter : 로그인 시도함. =====================================================================================");

        /**
            ID/PW를 받고

            1. 정상적인 값인지 로그인 시도 (`AuthenticationManager` 로 로그인)를 하면
                PrincipalDetailsService가 호출 → loadUserByUsername() 함수 실행됨.

            2. PrinciaplDetails를 세션에 담고

            3. JWT토큰을 만들어서 응답한다.
        */

        // 1. username, password 받기

//        try {
//            BufferedReader br = request.getReader();
//
//            String input = null;
//            while ((input = br.readLine()) != null){
//                log.info(input);
//            }
//        } catch (IOException e) {
//            throw new RuntimeException(e);
//        }

        ObjectMapper om = new ObjectMapper();
        try {
            User user = om.readValue(request.getInputStream(), User.class);
            log.info("요청 유저 정보 : {}", user);

            /** 토큰 생성 - form 로그인은 자동으로 만들어 주지만 , form로그인을 사용하지 않는 경우 직접 생성해주어야 한다. */
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // 생성한 토큰을 authenticationManager 에 넣어준다.
            // PrincipalDetailsService의 loadUserByUsername() 함수가 실행된 후 정상이면 authentication 이 리턴된다.
            // DB의 username과 password가 일치 한다.
            Authentication authentication =
                        authenticationManager.authenticate(authenticationToken);

            // Authentication 객체는 session 영역에 저장된다. => 로그인이 되었다는 뜻이다.
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            // principalDetails 객체가 생성되었다면 로그인이 정상적으로 되었다는 뜻이다.
            log.info("로그인 성공 : {}", principalDetails.getUser());

            /**
             * authentication 객체를 session 영역에 저장해야하고 그 방법이 return 해주는 것.
             * return 해주어 session 영역에 저장하는 이유는 권한 관리를 security 가 대신 해주기 때문이다.
             * 굳이 JWT 토큰을 사용하면서 세션을 만들 이유는 없다. 단지 권한 처리 때문에 session 에 저장한다.
             */
            return authentication; // authentication 객체가 session에 저장됨.
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * attemptAuthentication 실행 후 인증이 정상적으로 되었으면(로그인이 성공하면) successfulAuthentication 함수가 실행된다.
     * JWT 토큰을 만들어서 request 요청한 사용자에게 JWT 토큰을 response 해주면 된다.
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        log.info("######################################################### 인증이 성공하여 successfulAuthentication 메소드 실행됨. ");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        String jwtToken = JWT.create()
                .withSubject("cos토큰")
                .withExpiresAt(new Date(System.currentTimeMillis() + (60000 * 10))) // 토큰 만료 시간 ( 현재시간 + 단위 1/1000 초 )
                .withClaim("id", principalDetails.getUser().getId()) // 비공개 키 값 ( 넣고 싶은것 아무거나? )
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512("cos"));// Hash 암호 방식

        response.addHeader("Authorization", "Bearer " + jwtToken);
    }
}
