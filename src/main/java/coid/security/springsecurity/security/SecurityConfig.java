package coid.security.springsecurity.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
			.authorizeRequests()
			.antMatchers("/login").permitAll() 	// login 페이지는 인증이 안돼도 접근이 가능해야하기 때문에
			.antMatchers("/user").hasRole("USER")
			.antMatchers("/admin/pay").hasRole("ADMIN")
			.antMatchers("/admin/**").access("hasRole('ADMIN') or hasAnyRole('sys')")
			.anyRequest().authenticated();
		http
			.formLogin()
			.successHandler(new AuthenticationSuccessHandler() {
				@Override
				public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
					RequestCache requestCache = new HttpSessionRequestCache();
					SavedRequest savedRequest = requestCache.getRequest(request, response);
					String redirectUrl = savedRequest.getRedirectUrl();
					response.sendRedirect(redirectUrl);
				}
			});

		http
			.exceptionHandling()
			.authenticationEntryPoint(new AuthenticationEntryPoint() {   // 인증에 대한 예외
				@Override
				public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
					response.sendRedirect("/login");
				}
			})
			.accessDeniedHandler(new AccessDeniedHandler() {    // 권한에 대한 예외
				@Override
				public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
					response.sendRedirect("/denied");
				}
			});
		return http.build();
	}

	@Bean
	public InMemoryUserDetailsManager userDetailsService() {
		List<UserDetails> users = new ArrayList<>();
		users.add(User.builder().username("user").password("{noop}1111").roles("USER").build());
		users.add(User.builder().username("sys").password("{noop}11111").roles("SYS").build());
		users.add(User.builder().username("admin").password("{noop}11111").roles("ADMIN", "USER").build());
		return new InMemoryUserDetailsManager(users);
	}
}
