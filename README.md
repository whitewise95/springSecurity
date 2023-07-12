# 4-10 인증 실패 핸들러 : CustomAuthenticationFailureHandler

## SimpleUrlAuthenticationFailureHandler
> SimpleUrlAuthenticationFailureHandler를 상속할 클래스를 생성한다.
> 각 에러마다 핸들링을 할 수 있으며, 부모의 `onAuthenticationFailure` 메소드를 이용하면 디폴트 url로 이동이 가능하다.
```java
@Component
public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {

        String errorMessage = "Invalid Username or Password";

        if (exception instanceof BadCredentialsException) {
            errorMessage = "Invalid Username or Password";
        } else if (exception instanceof InsufficientAuthenticationException) {
            errorMessage = "Invalid Secret Key";
        }

        setDefaultFailureUrl("/login?error=true&exception=" + errorMessage);
        super.onAuthenticationFailure(request, response, exception);
    }
}
```

## /login 
> 에러여부와 에러메세지를 param으로 error와 exception로 전달하고 있기에 해당 핸들러를 아래와 같이 핸들링해준다.
```java
    @GetMapping("/login")
    public String login(@RequestParam(value = "error", required = false) Boolean error,
                        @RequestParam(value = "exception", required = false) String exception,
                        Model model){
        model.addAttribute("error", error);
        model.addAttribute("exception", exception);
        return "user/login/login";
    }
```

## SecurityConfig 설정
> AuthenticationFailureHandler를 주입해주고 ` .failureHandler(authenticationFailureHandler)` 를 추가해준다.
```java
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;
    private final AuthenticationDetailsSource authenticationDetailsSource;
    private final AuthenticationSuccessHandler authenticationSuccessHandler; 
    private final AuthenticationFailureHandler authenticationFailureHandler; //추가

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
                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login_proc") //login form의 action과 동일한 url로 유지해줘야한다.
                .authenticationDetailsSource(authenticationDetailsSource)
                .defaultSuccessUrl("/")
                .successHandler(authenticationSuccessHandler)
                .failureHandler(authenticationFailureHandler)  //추가
                .permitAll()


        ;
    }
}
```

## login.html 추가
> error와 exception를 받아 유저에게 메세지를 띄어줄 수 있도록 한다.
```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head th:replace="layout/header::userHead"></head>
<body>
<div th:replace="layout/top::header"></div>
<div class="container text-center">
    <div class="login-form d-flex justify-content-center">
        <div class="col-sm-5" style="margin-top: 30px;">
            <div class="panel">
                <p>아이디와 비밀번호를 입력해주세요</p>
            </div>
            <div th:if="${param.error}" class="form-group">
                <span th:text="${exception}" class="alert alert-danger">잘못된 아이디나 암호입니다</span>
            </div>
            <form th:action="@{/login_proc}" class="form-signin" method="post">
                <input type="hidden" th:value="secret2" name="secret_key" />
                <div class="form-group">
                    <input type="text" class="form-control" name="username" placeholder="아이디" required="required" autofocus="autofocus">
                </div>
                <div class="form-group">
                    <input type="password" class="form-control" name="password" placeholder="비밀번호" required="required">
                </div>
                <button type="submit" class="btn btn-lg btn-primary btn-block">로그인</button>
            </form>
        </div>
    </div>
</div>
</body>
</html>
```