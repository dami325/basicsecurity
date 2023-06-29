package io.security.basicsecurity;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 *
 * 폼 로그인 방식
 * http.formLogin()
 *                 .loginPage(“/login.html")   				// 사용자 정의 로그인 페이지
 *                 .defaultSuccessUrl("/home)				// 로그인 성공 후 이동 페이지
 * 	                .failureUrl(＂/login.html?error=true“)		// 로그인 실패 후 이동 페이지
 *                 .usernameParameter("username")			// 아이디 파라미터명 설정
 *                 .passwordParameter(“password”)			// 패스워드 파라미터명 설정
 *                 .loginProcessingUrl(“/login")			// 로그인 Form Action Url
 *                 .successHandler(loginSuccessHandler())		// 로그인 성공 후 핸들러
 *                 .failureHandler(loginFailureHandler())		// 로그인 실패 후 핸들러
 */

@Configuration
@EnableWebSecurity// 웹보안 활성화 시 명시 필수
public class SecurityConfig extends WebSecurityConfigurerAdapter {


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated();  // 인가 정책
        http
                .formLogin()
                .loginPage("/loginPage")// 로그인 페이지 url
                .defaultSuccessUrl("/")//인증 성공시
                .failureUrl("/login") //실패시 이동 url
                .usernameParameter("userId") // default = username
                .passwordParameter("passwd") // default = password
                .loginProcessingUrl("/login_proc")//from 태그의 action url
                .successHandler((request, response, authentication) -> { // 성공 핸들러
                    System.out.println("authentication.getName() = " + authentication.getName());
                    response.sendRedirect("/");
                })
                .failureHandler((request, response, exception) -> { // 실패 핸들러
                    System.out.println("exception.getMessage() = " + exception.getMessage());
                    response.sendRedirect("/login");
                })
                .permitAll()
        ;// 인증 정책
    }
}
