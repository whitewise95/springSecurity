package coid.security.springsecurity.security;

import coid.security.springsecurity.security.factory.UrlResourceMapFactoryBean;
import coid.security.springsecurity.security.handler.CustomAccessDeniedHandler;
import coid.security.springsecurity.security.handler.CustomAuthenticationFailureHandler;
import coid.security.springsecurity.security.handler.CustomAuthenticationSuccessHandler;
import coid.security.springsecurity.security.metadatasource.UrlFilterInvocationSecurityMetaDatsSource;
import coid.security.springsecurity.security.provider.CustomAuthenticationProvider;
import java.util.Arrays;
import java.util.List;

import coid.security.springsecurity.service.SecurityResourceService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;


@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@Order(1)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	private final UserDetailsService userDetailsService;
	private final AuthenticationDetailsSource authenticationDetailsSource;
	private final CustomAuthenticationSuccessHandler authenticationSuccessHandler;
	private final CustomAuthenticationFailureHandler authenticationFailureHandler;
	private final SecurityResourceService securityResourceService;


	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.authorizeRequests()
			.anyRequest().authenticated()
			.and()
			.exceptionHandling()  // 추가
			.accessDeniedHandler(accessDeniedHandler()) // 추가
			.and()
			.formLogin()
			.loginPage("/login")
			.loginProcessingUrl("/login_proc") // login form의 action과 동일한 url로 유지해줘야한다.
			.authenticationDetailsSource(authenticationDetailsSource)
			.defaultSuccessUrl("/")
			.successHandler(authenticationSuccessHandler)
			.failureHandler(authenticationFailureHandler)
			.permitAll();

		http
			.addFilterBefore(customFilterSecurityInterceptor(), FilterSecurityInterceptor.class);
	}

	private AccessDeniedHandler accessDeniedHandler() { // 추가
		CustomAccessDeniedHandler deniedHandler = new CustomAccessDeniedHandler();
		deniedHandler.setErrorPage("/denied");
		return deniedHandler;
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

	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

	@Bean
	public FilterSecurityInterceptor customFilterSecurityInterceptor() throws Exception {
		FilterSecurityInterceptor filterSecurityInterceptor = new FilterSecurityInterceptor();
		filterSecurityInterceptor.setSecurityMetadataSource(urlFilterInvocationSecurityMetadatasource());
		filterSecurityInterceptor.setAccessDecisionManager(affirmativeBased());
		filterSecurityInterceptor.setAuthenticationManager(authenticationManagerBean());
		return filterSecurityInterceptor;
	}

	@Bean
	public AccessDecisionManager affirmativeBased() {
		AffirmativeBased affirmativeBased = new AffirmativeBased(getAccessDecistionVoters());
		return affirmativeBased;
	}

	@Bean
	public List<AccessDecisionVoter<?>> getAccessDecistionVoters() {
		return Arrays.asList(new RoleVoter());
	}

	@Bean
	public FilterInvocationSecurityMetadataSource urlFilterInvocationSecurityMetadatasource() throws Exception {
		return new UrlFilterInvocationSecurityMetaDatsSource(urlResourceMapFactoryBean().getObject(), securityResourceService);
	}

	private UrlResourceMapFactoryBean urlResourceMapFactoryBean() {
		UrlResourceMapFactoryBean resourceMapFactoryBean = new UrlResourceMapFactoryBean();
		resourceMapFactoryBean.setSecurityResourceService(securityResourceService);
		return resourceMapFactoryBean;
	}
}