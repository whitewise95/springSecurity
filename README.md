# 4-9 인증 성공 핸들러 : CustomAuthenticationSuccessHandler

## SimpleUrlAuthenticationSuccessHandler 
> SimpleUrlAuthenticationSuccessHandler를 상속할 클래스를 생성해 로그인시 이전 접속하려했던 주소를 가지고 있는 `requestCache` 와  `redirect`해줄 RedirectStrategy 를 선언해준다.
```java
@Component
public class CustomAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private RequestCache requestCache = new HttpSessionRequestCache();
    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        setDefaultTargetUrl("/");  // 이전정보가 없을 경우 디폴트 url 설정

        SavedRequest savedRequest = requestCache.getRequest(request, response); 
        if (savedRequest != null) { // 로그인시 이전정보가 없을 경우 생성되지 않아서 null체크
            String redirectUrl = savedRequest.getRedirectUrl();
            redirectStrategy.sendRedirect(request, response, redirectUrl);
        } else {
            redirectStrategy.sendRedirect(request, response, getDefaultTargetUrl());
        }
    }
}
```

## SecurityConfig 설정
> AuthenticationSuccessHandler 주입해주고 ` .successHandler(authenticationSuccessHandler) ` 를 추가해 생성해준 `CustomAuthenticationSuccessHandler` 를 사용할 수 있도록한다.
```java
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;
    private final AuthenticationDetailsSource authenticationDetailsSource;
    private final AuthenticationSuccessHandler authenticationSuccessHandler;  // 추가 

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
                .authenticationDetailsSource(authenticationDetailsSource)
                .defaultSuccessUrl("/")
                .successHandler(authenticationSuccessHandler)   // 추가 
                .permitAll()


        ;
    }
}
```