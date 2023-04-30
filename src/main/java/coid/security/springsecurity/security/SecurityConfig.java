package coid.security.springsecurity.security;

import java.security.cert.Extension;
import java.util.ArrayList;
import java.util.List;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
			.authorizeRequests()
			.antMatchers("/", "/users").permitAll()
			.antMatchers("/mypage").hasRole("USER")
			.antMatchers("/messages").hasRole("MANAGER, USER")
			.antMatchers("/config").hasRole("ADMIN, MANAGER, USER")
			.anyRequest().authenticated()

			.and()
			.formLogin();

		return http.build();
	}

	@Bean
	public WebSecurityCustomizer webSecurityCustomizer() {
		return (web) -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
	}

	@Bean
	public InMemoryUserDetailsManager userDetailsService() {
		List<UserDetails> users = new ArrayList<>();

		String password = passwordEncoder().encode("1111");

		users.add(User.builder().username("user").password(password).roles("USER").build());
		users.add(User.builder().username("manager").password(password).roles("MANAGER").build());
		users.add(User.builder().username("admin").password(password).roles("ADMIN").build());
		return new InMemoryUserDetailsManager(users);
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}
}