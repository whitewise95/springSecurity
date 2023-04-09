package coid.security.springsecurity.security;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
			.authorizeRequests()
			.anyRequest().authenticated();
		http
			.formLogin()
			.loginPage("/loginPage")             //사용자 정의 로그인 페이지

			//region 핸들러없이 바로 이동페이지 설정
			.defaultSuccessUrl("/")		         // 로그인 성공 후 이동 페이지
			.failureUrl("/login")   			 // 로그인 실패 후 이동페이지
			//endregion

			//region 제공해주는 로그인페이지 파라마터 name 및 Action 셋팅
			.usernameParameter("userId")    	 // 아이디 파라미터명 설정
			.passwordParameter("passwd")     	 //패스워드 파라미터명 설정
			.loginProcessingUrl("/login_proc")   //로그인 form Action url 설정
			//endregion

			// 로그인 성공후 핸들러
			.successHandler(new AuthenticationSuccessHandler() {
				@Override
				public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
					System.out.println("authentication" + authentication.getName());
					response.sendRedirect("/");
				}
			})


			// 로그인 실패 후 핸들러
			.failureHandler(new AuthenticationFailureHandler() {
				@Override
				public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
					System.out.println("exception" + exception.getMessage());
					response.sendRedirect("/login");
				}
			})

			//로그인페이지를 모든 사용자가 접근 가능하도록 설정
			.permitAll();

		return http.build();
	}

}
