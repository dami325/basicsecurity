package io.security.basicsecurity;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpSession;

@RestController
public class SecurityController {

    @GetMapping("/")
    public String index(HttpSession session) {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // 세션에도 저장됨 꺼내 쓰는방법 객체의 구문은 틀려도 동일한 객체를 참조함(객체의 주소값이 같음)
        SecurityContext context = (SecurityContext) session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication authentication1 = context.getAuthentication();

        return "home";
    }

    @GetMapping("/thread")
    public String thread(){

        /**
         * 아래의 코드는
         * 스프링 시큐리티의 기본 모드인 MODE_THREADLOCAL 로는 자식 객체의 Thread에 공유할 수 없음
         * authentication 결과값 null
         *
         * 설정 클래스에서 MODE_INHERITABLETHREADLOCAL로 변경 해야 객체를 공유 할 수 있음
         *
         * SecurityConfig에서 아래의 설정을 해줘야함
         * SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
         */
        new Thread(
                () -> {
                    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                }
        ).start();

        return "thread";

    }

    @GetMapping("/loginPage")
    public String loginPage() {

        return "loginPage";
    }

    @GetMapping("/user")
    public String user() {
        return "user";
    }


    @GetMapping("/admin/pay")
    public String adminPay() {
        return "adminPay";
    }

    @GetMapping("/admin/**")
    public String admin() {
        return "admin/**";
    }


    @GetMapping("/denied")
    public String denied() {
        return "denied";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

}
