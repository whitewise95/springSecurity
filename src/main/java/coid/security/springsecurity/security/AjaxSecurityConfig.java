package coid.security.springsecurity.security;

import coid.security.springsecurity.security.common.AjaxLoginAuthenticationEntryPoint;
import coid.security.springsecurity.security.filter.AjaxLoginProcessingFilter;
import coid.security.springsecurity.security.handler.AjaxAccessDeniedHandler;
import coid.security.springsecurity.security.handler.AjaxAuthenticationFailureHandler;
import coid.security.springsecurity.security.handler.AjaxAuthenticationSuccessHandler;
import coid.security.springsecurity.security.provider.AjaxAuthenticationProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

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

	@Bean
	public AuthenticationSuccessHandler ajaxAuthenticationSuccessHandler() {
		return new AjaxAuthenticationSuccessHandler();
	}

	@Bean
	public AuthenticationFailureHandler ajaxAuthenticationFailureHandler() {
		return new AjaxAuthenticationFailureHandler();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.antMatcher("/api/**") // 이 엔드포인트로만 동작하도록 설정
			.authorizeRequests()
			.antMatchers("/api/messages").hasRole("MANAGER")
			.anyRequest().authenticated()
			.and()
			.addFilterBefore(ajaxLoginProcessingFilter(), UsernamePasswordAuthenticationFilter.class);

		http
			.exceptionHandling()
			.authenticationEntryPoint(new AjaxLoginAuthenticationEntryPoint())
			.accessDeniedHandler(ajaxAccessDeniedHandler());

		http.csrf().disable();
	}

	@Bean
	public AccessDeniedHandler ajaxAccessDeniedHandler() {
		return new AjaxAccessDeniedHandler();
	}

	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Bean
	public AjaxLoginProcessingFilter ajaxLoginProcessingFilter() throws Exception {
		AjaxLoginProcessingFilter ajaxLoginProcessingFilter = new AjaxLoginProcessingFilter();
		ajaxLoginProcessingFilter.setAuthenticationManager(authenticationManagerBean());
		ajaxLoginProcessingFilter.setAuthenticationSuccessHandler(ajaxAuthenticationSuccessHandler());
		ajaxLoginProcessingFilter.setAuthenticationFailureHandler(ajaxAuthenticationFailureHandler());
		return ajaxLoginProcessingFilter;
	}
}
