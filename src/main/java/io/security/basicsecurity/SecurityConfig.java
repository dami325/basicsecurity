package io.security.basicsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/**
 *
 * 폼 로그인 방식
 * http.formLogin()
 *     .loginPage(“/login.html")   				// 사용자 정의 로그인 페이지
 *     .defaultSuccessUrl("/home)				// 로그인 성공 후 이동 페이지
 * 	    .failureUrl(＂/login.html?error=true“)		// 로그인 실패 후 이동 페이지
 *     .usernameParameter("username")			// 아이디 파라미터명 설정
 *     .passwordParameter(“password”)			// 패스워드 파라미터명 설정
 *     .loginProcessingUrl(“/login")			// 로그인 Form Action Url
 *     .successHandler(loginSuccessHandler())		// 로그인 성공 후 핸들러
 *     .failureHandler(loginFailureHandler())		// 로그인 실패 후 핸들러
 *
 * http.logout() : 로그아웃 기능이 작동함, 로그아웃 처리
 *     .logoutUrl(＂/logout＂)				// 로그아웃 처리 URL default = /logout
 * 	   .logoutSuccessUrl(＂/login＂)			// 로그아웃 성공 후 이동페이지
 *     .deleteCookies(＂JSESSIONID“, ＂remember-me＂) 	// 로그아웃 후 쿠키 삭제
 * 	   .addLogoutHandler(logoutHandler())		 // 로그아웃 핸들러
 *     .logoutSuccessHandler(logoutSuccessHandler()) 	// 로그아웃 성공 후 핸들러
 *
 *
 * http.rememberMe()
 * 		.rememberMeParameter(“remember”) // 기본 파라미터명은 remember-me
 * 		.tokenValiditySeconds(3600) // Default 는 14일
 * 		.alwaysRemember(true) // 리멤버 미 기능이 활성화되지 않아도 항상 실행
 * 		.userDetailsService(userDetailsService)
 */

@Configuration
@EnableWebSecurity// 웹보안 활성화 시 명시 필수
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated();  // 인가 정책
        http
                .formLogin()
//                .loginPage("/login")// 로그인 페이지 url
//                .defaultSuccessUrl("/")//인증 성공시
//                .failureUrl("/login") //실패시 이동 url
//                .usernameParameter("userId") // default = username
//                .passwordParameter("passwd") // default = password
//                .loginProcessingUrl("/login_proc")//from 태그의 action url
//                .successHandler((request, response, authentication) -> { // 성공 핸들러
//                    System.out.println("authentication.getName() = " + authentication.getName());
//                    response.sendRedirect("/");
//                })
//                .failureHandler((request, response, exception) -> { // 실패 핸들러
//                    System.out.println("exception.getMessage() = " + exception.getMessage());
//                    response.sendRedirect("/login");
//                })
//                .permitAll()
        ;// 인증 정책

        http
                .logout()
                .logoutUrl("/logout") // 원칙적으로 스프링 시큐리티는 post 방식으로 로그아웃함 커스텀 시 원칙을 지키는게 좋음
                .logoutSuccessUrl("/login")
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                        HttpSession session = request.getSession();
                        session.invalidate(); // 세션 무효화
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                }) // 핸들러는 다양한 로직을 더 많이 구현할 수 있음
                .deleteCookies("remember-me") // 삭제하고싶은 쿠키명
        ;

        http
                .rememberMe()
                .rememberMeParameter("remember") //기본값은 remember-me
                .tokenValiditySeconds(3600) //기본은 14일
                .userDetailsService(userDetailsService)
        ;
    }
}
