package coid.security.springsecurity.security.filter;

import coid.security.springsecurity.dto.AccountDto;
import coid.security.springsecurity.dto.AccountDtoMapper;
import coid.security.springsecurity.security.token.AjaxAuthenticationToken;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.BufferedReader;
import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;

public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {

	@Autowired
	private ObjectMapper objectMapper;

	public AjaxLoginProcessingFilter() {
		super(new AntPathRequestMatcher("/api/login"));
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

		if (isAjax(request)) {
			throw new IllegalStateException("Authentication is not supported");
		}

		AccountDto accountDto = objectMapper.readValue(request.getReader(), AccountDto.class);
		if (StringUtils.isEmpty(accountDto.getUsername()) || StringUtils.isEmpty(accountDto.getPassword())) {
			throw new IllegalArgumentException("Username or Password is empty");
		}

		AjaxAuthenticationToken ajaxAuthenticationToken = new AjaxAuthenticationToken(accountDto.getUsername(), accountDto.getPassword());
		setDetails(request, ajaxAuthenticationToken);
		return getAuthenticationManager().authenticate(ajaxAuthenticationToken);
	}

	private boolean isAjax(HttpServletRequest request) {
		if ("XMLHttpRequest".equals(request.getHeader("X-RequestedWith"))) {
			return true;
		}

		return false;
	}

	protected void setDetails(HttpServletRequest request, AjaxAuthenticationToken ajaxAuthenticationToken) {
		ajaxAuthenticationToken.setDetails(this.authenticationDetailsSource.buildDetails(request));
	}
}
