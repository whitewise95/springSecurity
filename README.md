# 5-2) 인증 필터 - AjaxAuthenticationFilter

## AbstractAuthenticationProcessingFilter 상속
- 생성시 요청한 uri가 '/api/login' 가 맞는지 체크한다.
- isAjax() 메소드를 만들어 Ajax로 요청한 부분이 맞는지 체크한다. 
- AjaxAuthenticationToken을 만들어 리턴해준다.
```java
public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {

	public AjaxLoginProcessingFilter() {
		super(new AntPathRequestMatcher("/api/login"));
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

		if (isAjax(request)) {
			throw new IllegalStateException("Authentication is not supported");
		}

		AccountDto accountDto = AccountDtoMapper.INSTANCE.login(request.getReader());
		if (StringUtils.isEmpty(accountDto.getUsername()) || StringUtils.isEmpty(accountDto.getPassword())) {
			throw new IllegalArgumentException("Username or Password is empty");
		}

		AjaxAuthenticationToken ajaxAuthenticationToken = new AjaxAuthenticationToken(accountDto.getUsername(), accountDto.getPassword());
		return getAuthenticationManager().authenticate(ajaxAuthenticationToken);
	}

	private boolean isAjax(HttpServletRequest request) {
		if ("XMLHttpRequest".equals(request.getHeader("X-RequestedWith"))) {
			return true;
		}

		return false;
	}
}
```

## AbstractAuthenticationToken 상속
- UsernamePasswordAuthenticationToken 클래스의 내용을 복사하여 필요없는 부분을 제거한다.
- AjaxAuthenticationToken클래스와 맞춰서 수정해준다.
```java
package coid.security.springsecurity.security.token;

import java.util.Collection;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.Assert;

public class AjaxAuthenticationToken extends AbstractAuthenticationToken {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	private final Object principal;
	private Object credentials;

	/**
	 * 인증전
	 */
	public AjaxAuthenticationToken(Object principal, Object credentials) {
		super(null);
		this.principal = principal;
		this.credentials = credentials;
		setAuthenticated(false);
	}

	/**
	 * 인증후
	 */
	public AjaxAuthenticationToken(Object principal, Object credentials,
								   Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.principal = principal;
		this.credentials = credentials;
		super.setAuthenticated(true); // must use super, as we override
	}

	public static UsernamePasswordAuthenticationToken unauthenticated(Object principal, Object credentials) {
		return new UsernamePasswordAuthenticationToken(principal, credentials);
	}

	public static UsernamePasswordAuthenticationToken authenticated(Object principal, Object credentials,
																	Collection<? extends GrantedAuthority> authorities) {
		return new UsernamePasswordAuthenticationToken(principal, credentials, authorities);
	}

	@Override
	public Object getCredentials() {
		return this.credentials;
	}

	@Override
	public Object getPrincipal() {
		return this.principal;
	}

	@Override
	public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
		Assert.isTrue(!isAuthenticated,
					  "Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
		super.setAuthenticated(false);
	}

	@Override
	public void eraseCredentials() {
		super.eraseCredentials();
		this.credentials = null;
	}
}

```

## SecurityConfig 로직 추가 
- `authenticationManagerBean()` 를 오버라이딩해준다.
- `ajaxLoginProcessingFilter()`와 같이 ajaxLoginProcessingFilter를 생성하고 authenticationManagerBean를 주입시켜주는 메소드를 생성한다.
- `addFilterBefore` 에 `ajaxLoginProcessingFilter()` 를 `UsernamePasswordAuthenticationFilter.class` 보다 먼저 작동해주도록 해준다.
```java
http.addFilterBefore(ajaxLoginProcessingFilter(), UsernamePasswordAuthenticationFilter.class);

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
```