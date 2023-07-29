# 5-4) 인증 핸들러 - AjaxAuthenticationSuccessHandler, AjaxAuthenticationFailureHandler

## AuthenticationSuccessHandler 구현
- Ajax 비동기 통신이기 때문에 리다이렉트 하는게 아니라 원하는 값을 바디에 담아 응답하는 방식이다.
```java
@Component
public class AjaxAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

	private ObjectMapper objectMapper = new ObjectMapper();

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
		Account account = (Account) authentication.getPrincipal();

		response.setStatus(HttpStatus.OK.value());
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);

		objectMapper.writeValue(response.getWriter(), account);
	}
}
```

## AuthenticationFailureHandler 구현
```java
@Component
public class AjaxAuthenticationFailureHandler implements AuthenticationFailureHandler {

	private ObjectMapper objectMapper = new ObjectMapper();

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
		String errMsg = "Invalid Username or Password";

		if (exception instanceof BadCredentialsException) {
			errMsg = "Invalid Username or Password";
		} else if (exception instanceof InsufficientAuthenticationException) {
			errMsg = "Invalid Secret Key";
		}

		response.setStatus(HttpStatus.UNAUTHORIZED.value());
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		objectMapper.writeValue(response.getWriter(), errMsg);
	}
}
```

## AjaxSecurityConfig 설정
- ajaxAuthenticationSuccessHandler와 ajaxAuthenticationFailureHandler를 사용할 수 있게 객체를 생성하는 메소드를 각각 만든다.
- AjaxLoginProcessingFilter를 반환하는 메소드에서 두 객체를 설정해준다.
```java
	@Bean
	public AuthenticationSuccessHandler ajaxAuthenticationSuccessHandler() {
		return new AjaxAuthenticationSuccessHandler();
	}

	@Bean
	public AuthenticationFailureHandler ajaxAuthenticationFailureHandler() {
		return new AjaxAuthenticationFailureHandler();
	}

    @Bean
    public AjaxLoginProcessingFilter ajaxLoginProcessingFilter() throws Exception {
        AjaxLoginProcessingFilter ajaxLoginProcessingFilter = new AjaxLoginProcessingFilter();
        ajaxLoginProcessingFilter.setAuthenticationManager(authenticationManagerBean());
        ajaxLoginProcessingFilter.setAuthenticationSuccessHandler(ajaxAuthenticationSuccessHandler());
        ajaxLoginProcessingFilter.setAuthenticationFailureHandler(ajaxAuthenticationFailureHandler());
        return ajaxLoginProcessingFilter;
    }
```

