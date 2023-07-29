# 5-3) 인증 처리자 - AjaxAuthenticationProvider

## AuthenticationProvider 구현
- AuthenticationProvider를 구현할 클래스 `AjaxAuthenticationProvider` 를 만들어 로직을 구성한다.
```java
@Service
@RequiredArgsConstructor
public class AjaxAuthenticationProvider implements AuthenticationProvider {

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

		return new AjaxAuthenticationToken(accountContext.getAccount(), null, accountContext.getAuthorities());
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return AjaxAuthenticationToken.class.isAssignableFrom(authentication);
	}
}
```

## AjaxSecurityConfig
- `AjaxSecurityConfig`를 만들어 SecurityConfig에서 Ajax설정을 분리 시킨다. 
- `@Order`를 사용해 어떤 config를 먼저 사용할지 설정한다. 
```java
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@Order(0)
public class AjaxSecurityConfig extends WebSecurityConfigurerAdapter {

	private final AjaxAuthenticationProvider authenticationProvider;

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(authenticationProvider);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.antMatcher("/api/**") // 이 엔드포인트로만 동작하도록 설정
			.authorizeRequests()
			.anyRequest().authenticated()
			.and()
			.addFilterBefore(ajaxLoginProcessingFilter(), UsernamePasswordAuthenticationFilter.class);
		http.csrf().disable();
	}

	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Bean
	public AjaxLoginProcessingFilter ajaxLoginProcessingFilter() throws Exception {
		AjaxLoginProcessingFilter ajaxLoginProcessingFilter = new AjaxLoginProcessingFilter();
		ajaxLoginProcessingFilter.setAuthenticationManager(authenticationManagerBean());
		return ajaxLoginProcessingFilter;
	}
}
```

## 테스트
- `.http` 파일을 만들어 테스트를 진행한다.
```http request
POST http://localhost:8090/api/login
Content-Type: application/json
X-Requested-With: XMLHttpRequest

{
  "username": "user",
  "password": "1111"
}
```