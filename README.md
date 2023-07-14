# 4-11) 인증 거부 처리 - Access Denied
> 권한이 없는 회원을 핸들링 

## AccessDeniedHandler
> AccessDeniedHandler 구현하는 클래스 생성 `deniedUrl` 로 `response.sendRedirect(deniedUrl);` 한다.  

```java
package coid.security.springsecurity.security.handler;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    private String errorPage;

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        String deniedUrl = errorPage + "?exception=" + accessDeniedException.getMessage();
        response.sendRedirect(deniedUrl);
    }

    public void setErrorPage(String errorPage) {
        this.errorPage = errorPage;
    }
}
```  

## SecurityConfig 설정
> `.and()` 이후 `.exceptionHandling() ` 와  `.accessDeniedHandler(accessDeniedHandler())` 를 작성한다.
> `accessDeniedHandler()` 는 `AccessDeniedHandler` 를 구현한 클래스를 반환하도록 한다.
```java
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;
    private final AuthenticationDetailsSource authenticationDetailsSource;
    private final AuthenticationSuccessHandler authenticationSuccessHandler;
    private final AuthenticationFailureHandler authenticationFailureHandler;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/", "/users", "/login*").permitAll()
                .antMatchers("/mypage").hasRole("USER")
                .antMatchers("/messages").hasRole("MANAGER, USER")
                .antMatchers("/config").hasRole("ADMIN, MANAGER, USER")
                .anyRequest().authenticated()
        .and()
                .exceptionHandling()  //추가
                .accessDeniedHandler(accessDeniedHandler()) //추가
        .and()
                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login_proc") //login form의 action과 동일한 url로 유지해줘야한다.
                .authenticationDetailsSource(authenticationDetailsSource)
                .defaultSuccessUrl("/")
                .successHandler(authenticationSuccessHandler)
                .failureHandler(authenticationFailureHandler)
                .permitAll()


        ;
    }

    private AccessDeniedHandler accessDeniedHandler() { //추가
        CustomAccessDeniedHandler deniedHandler = new CustomAccessDeniedHandler();
        deniedHandler.setErrorPage("/denied");
        return deniedHandler;
    }
}
```

## Controller 메소드추가
> `sendRedirect` 하는 url를 핸들링해줄 메소드를 생성한다.           

```java
@GetMapping("/denied")
public String accessDenied(@RequestParam(value = "exception", required = false) String exception,
        Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Account account = (Account) authentication.getPrincipal();
        model.addAttribute("username", account.getUsername());
        model.addAttribute("exception", exception);
        return "user/login/denied";
}
```  

## html 추가
>  Controller 메소드에서 리턴해준는 경로에 html를 생성한다.

```html
<!DOCTYPE html>
<html lang="ko" xmlns:th="http://www.thymeleaf.org">
<head th:replace="layout/header::userHead"></head>
<body>
<div th:replace="layout/top::header"></div>
<div class="container">
  <div class="row align-items-start">
    <nav class="col-md-2 d-none d-md-block bg-light sidebar">
      <div class="sidebar-sticky">
        <ul class="nav flex-column">
          <li class="nav-item">
            <div style="padding-top:10px;" class="nav flex-column nav-pills" aria-orientation="vertical">
              <a th:href="@{/}" style="margin:5px;" class="nav-link  text-primary">대시보드</a>
              <a th:href="@{/mypage}" style="margin:5px;" class="nav-link text-primary">마이페이지</a>
              <a th:href="@{/messages}" style="margin:5px;" class="nav-link text-primary">메시지</a>
              <a th:href="@{/config}" style="margin:5px;" class="nav-link text-primary">환경설정</a>
            </div>
          </li>
        </ul>
      </div>
    </nav>
    <div style="padding-top:50px;"  class="col">
      <div class="container text-center">
        <h1><span th:text="${username}" class="alert alert-danger" />님은 접근 권한이 없습니다.</h1>
        <br />
        <h3 th:text="${exception}"></h3>
      </div>
    </div>
  </div>
</div>
<div th:replace="layout/footer::footer"></div>
</body>
</html>
```