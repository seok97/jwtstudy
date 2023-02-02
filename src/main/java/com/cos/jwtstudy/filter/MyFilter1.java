package com.cos.jwtstudy.filter;


import lombok.extern.slf4j.Slf4j;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

@Slf4j
public class MyFilter1 implements Filter {

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {

        // 다운캐스팅
        HttpServletRequest req = (HttpServletRequest) servletRequest;
        HttpServletResponse res = (HttpServletResponse) servletResponse;

        /**
         * 토큰 = cos 을 만들어야 한다. id, pw 가 정상적으로 들어와 로그인이 완료 되면 토큰을 만들어주고 응답한다.
         * 요청할 떄 마다 header에 Authorization에 value 값으로 토큰을 가지고 오고
         * 그때 토큰이 넘어오면 이 토큰이 내가 만든 토큰이 맞는지 검증만 하면된다. ( RSA, HS256 )
         */
        // post 요청만 실행
        if(req.getMethod().equals("POST")){
            System.out.println("######### post 요청 ");
            String headerAuth = req.getHeader("Authorization");
            System.out.println("authorization : " + headerAuth);

            if(headerAuth.equals("cos")){
                filterChain.doFilter(req, res);
            }else {
                PrintWriter outPrintWriter = res.getWriter();
                outPrintWriter.println("인증안됨");
            }
        }
    }
}
