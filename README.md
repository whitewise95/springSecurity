# 4-8 인증 부가 기능 - WebAuthenticationDetails, AuthenticationDetailsSource
> 스프링 시큐리티는 사용자가 입력한 id와 pw를 받아 인증을 한다. 그 외에 정보를 받을 수 있도록 WebAuthenticationDetails, AuthenticationDetailsSource 가 부가 기능을 제공한다.

##  WebAuthenticationDetails
> FormWebAuthenticationDetails 클래스를 만들어 WebAuthenticationDetails를 상속받아 생성자를 만들어준다.
> 생성자는 HttpServletRequest를 받아 사용자가 넘겨준 데이터를 저장하는 역활을 한다.
```java
public class FormWebAuthenticationDetails extends WebAuthenticationDetails {

    private String secretKey;

    public FormWebAuthenticationDetails(HttpServletRequest request) {
        super(request);
        secretKey = request.getParameter("secret_key");
    }

    public String getSecretKey() {
        return secretKey;
    }
}
```


## FormAuthenticationDetailSource
> FormAuthenticationDetailSource 클래스를 만들어 AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> 를 구현한다.
> 오버라이딩으로 전에 만든 FormWebAuthenticationDetails 를 생성해 리턴해준다.
```java
@Component
public class FormAuthenticationDetailSource implements AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> {
    @Override
    public WebAuthenticationDetails buildDetails(HttpServletRequest context) {
        return new FormWebAuthenticationDetails(context);
    }
}
```

## CustomAuthenticationProvider 로직 추가
>   리턴한 FormWebAuthenticationDetails 객체는 `authentication.getDetails();` 로 호출할 수 있다.

### 추가한 로직
```java
        FormWebAuthenticationDetails details = (FormWebAuthenticationDetails) authentication.getDetails();
        String secretKey = details.getSecretKey();
        if (secretKey == null || !"secret".equals(secretKey)) {
            throw new InsufficientAuthenticationException("InsufficientAuthenticationException");
        }
```

### 전체로직
```java
@Service
@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = (String) authentication.getCredentials();

        AccountContext accountContext = (AccountContext) userDetailsService.loadUserByUsername(username);

        if (!passwordEncoder.matches(password, accountContext.getAccount().getPassword())) {
            throw new BadCredentialsException("BadCredentialsException");
        }

        FormWebAuthenticationDetails details = (FormWebAuthenticationDetails) authentication.getDetails();
        String secretKey = details.getSecretKey();
        if (secretKey == null || !"secret".equals(secretKey)) {
            throw new InsufficientAuthenticationException("InsufficientAuthenticationException");
        }
        return new UsernamePasswordAuthenticationToken(accountContext.getAccount(), null, accountContext.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
```


## SecurityConfig 로직 추가
> 빈으로 등록한 FormAuthenticationDetailSource 클래스를 의존성주입해주고 authenticationDetailsSource 인자에 넣어준다.
```java
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;
    private final AuthenticationDetailsSource authenticationDetailsSource;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/", "/users").permitAll()
                .antMatchers("/mypage").hasRole("USER")
                .antMatchers("/messages").hasRole("MANAGER, USER")
                .antMatchers("/config").hasRole("ADMIN, MANAGER, USER")
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login_proc") //login form의 action과 동일한 url로 유지해줘야한다.
                .authenticationDetailsSource(authenticationDetailsSource)  // 추가한 로직
                .defaultSuccessUrl("/")
                .permitAll()


        ;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authenticationProvider());
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        return new CustomAuthenticationProvider(userDetailsService, passwordEncoder());
    }

    @Override
    public void configure(WebSecurity web) {
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
```

## login.html
> `   <input type="hidden" th:value="secret" name="secret_key" />` 로직을 추가해 secret 값을 넘긴다.
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
                <input type="hidden" th:value="secret" name="secret_key" />
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
