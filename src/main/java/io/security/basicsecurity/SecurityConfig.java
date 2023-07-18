package io.security.basicsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/**
 * 폼 로그인 방식
 * http.formLogin()
 * .loginPage(“/login.html")   				// 사용자 정의 로그인 페이지
 * .defaultSuccessUrl("/home)				// 로그인 성공 후 이동 페이지
 * .failureUrl(＂/login.html?error=true“)		// 로그인 실패 후 이동 페이지
 * .usernameParameter("username")			// 아이디 파라미터명 설정
 * .passwordParameter(“password”)			// 패스워드 파라미터명 설정
 * .loginProcessingUrl(“/login")			// 로그인 Form Action Url
 * .successHandler(loginSuccessHandler())		// 로그인 성공 후 핸들러
 * .failureHandler(loginFailureHandler())		// 로그인 실패 후 핸들러
 *
 *
 * http.logout() : 로그아웃 기능이 작동함, 로그아웃 처리
 * .logoutUrl(＂/logout＂)				// 로그아웃 처리 URL default = /logout
 * .logoutSuccessUrl(＂/login＂)			// 로그아웃 성공 후 이동페이지
 * .deleteCookies(＂JSESSIONID“, ＂remember-me＂) 	// 로그아웃 후 쿠키 삭제
 * .addLogoutHandler(logoutHandler())		 // 로그아웃 핸들러
 * .logoutSuccessHandler(logoutSuccessHandler()) 	// 로그아웃 성공 후 핸들러
 *
 * http.rememberMe()
 * .rememberMeParameter(“remember”)        // 기본 파라미터명은 remember-me
 * .tokenValiditySeconds(3600)             // Default 는 14일
 * .alwaysRemember(true)                   // 리멤버 미 기능이 활성화되지 않아도 항상 실행
 * .userDetailsService(userDetailsService)
 *
 * http.sessionManagement()
 * .maximumSessions(1)                    // 최대 허용 가능 세션 수 , -1 : 무제한 로그인 세션 허용
 * .maxSessionsPreventsLogin(true)        // true : 동시 로그인 차단함(이미 로그인 중인 계정이라면, 지금 로그인 하는 사람 차단),  false : 기존 세션 만료(default)
 * .invalidSessionUrl("/invalid")         // 세션이 유효하지 않을 때 이동 할 페이지
 * .expiredUrl("/expired ")  	             // 세션이 만료된 경우 이동 할 페이지
 *
 *      http.exceptionHandling()
 * 		.authenticationEntryPoint(authenticationEntryPoint())    // 인증실패 시 처리  - 인증예외
 * 		.accessDeniedHandler(accessDeniedHandler()) 			 // 인증실패 시 처리 - 인가예외
 */

@Configuration
@EnableWebSecurity// 웹보안 활성화 시 명시 필수
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    UserDetailsService userDetailsService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN","SYS","USER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/login").permitAll() // 이 설정을 안해주면 아래의  .anyRequest().authenticated() 설정에 의해 페이지 접근이 안됨
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").hasRole("ADMIN") /** 넓은것보다 구체적인 범위를 항상 먼저 써야 먼저 인가처리가 된다.!!**/
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
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
                .successHandler((request, response, authentication) -> {
                    RequestCache requestCache = new HttpSessionRequestCache();
                    SavedRequest savedRequest = requestCache.getRequest(request, response); // 원래 사용자가 가고자 했던 정보가 저장되어 있음
                    String redirectUrl = savedRequest.getRedirectUrl();// 원래 가고자했던 url
                    response.sendRedirect(redirectUrl);//원래 가고자 했던 url로 보내준다
                })
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

        //동시 세션 제어
        http
                .sessionManagement()
                .maximumSessions(1)
                .maxSessionsPreventsLogin(false) // default = false// 현재 인증하고있는 사용자 인증 실패 하게 하는 전략 = true
        ;

        // 세션 고정 보호
//        http.sessionManagement()
//                .sessionFixation().changeSessionId();// 설정안해도 기본으로 해줌 default

        // 인증 인가 예외
        http
                .exceptionHandling()
//                .authenticationEntryPoint((request, response, authException) -> response.sendRedirect("/login")) // 직접 적으면 우리가 만든 페이지로 이동함
                .accessDeniedHandler((request, response, accessDeniedException) -> response.sendRedirect("/denied"))
                ;
    }
}
