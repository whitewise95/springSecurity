package coid.security.springsecurity.security;

import java.util.ArrayList;
import java.util.List;
import javax.sql.DataSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.ldap.LdapBindAuthenticationManagerFactory;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
			.authorizeRequests()
			.antMatchers("/user").hasRole("USER")
			.antMatchers("/admin/pay").hasRole("ADMIN")
			.antMatchers("/admin/**").access("hasRole('ADMIN') or hasAnyRole('sys')")
			.anyRequest().authenticated();
		http
			.formLogin();
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
