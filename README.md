# 5-5) 인증 및 인가 예외 처리 - AuthenticationEntryPoint, AccessDeniedHandler

## AuthenticationEntryPoint
- 익명사용자가 인증이 필요한 자원에 접근할 경우 핸들링할 수 있다.
- `AuthenticationEntryPoint` 를 구현하고 해당 에러를 Response 할 수 있다.
```java
public class AjaxLoginAuthenticationEntryPoint implements AuthenticationEntryPoint {

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
		response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "UnAuthorized");
	}
}
```

## AccessDeniedHandler
- 로그인된 회원이 권한이 필요한 자원에 접근시 권한이 맞지 않을 경우 핸들링할 수 있다.
- `AccessDeniedHandler` 를 구현해서 해당 에러를 Response 할 수 있다.
```java
public class AjaxAccessDeniedHandler implements AccessDeniedHandler {

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
		response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access is denied");
	}
}
```

## AjaxSecurityConfig 설정
```java
	http
			.exceptionHandling()
			.authenticationEntryPoint(new AjaxLoginAuthenticationEntryPoint())
			.accessDeniedHandler(ajaxAccessDeniedHandler());

    @Bean
    public AccessDeniedHandler ajaxAccessDeniedHandler() {
        return new AjaxAccessDeniedHandler();
        }
```

## 테스트
```http request
POST http://localhost:8090/api/login
Content-Type: application/json
X-Requested-With: XMLHttpRequest

{
  "username": "user",
  "password": "1111"
}
###
POST http://localhost:8090/api/login
Content-Type: application/json
X-Requested-With: XMLHttpRequest

{
"username": "manager",
"password": "1111"
}

###
GET http://localhost:8090/api/messages
Content-Type: application/json
X-Requested-With: XMLHttpRequest

```