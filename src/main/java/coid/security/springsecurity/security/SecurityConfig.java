package coid.security.springsecurity.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

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
		// .loginPage("/login")             //사용자 정의 로그인 페이지

		// 	//region 핸들러없이 바로 이동페이지 설정
		// 	// .defaultSuccessUrl("/")                 // 로그인 성공 후 이동 페이지
		// 	// .failureUrl("/login")             // 로그인 실패 후 이동페이지
		// 	//endregion
		//
		// 	//region 제공해주는 로그인페이지 파라마터 name 및 Action 셋팅
		// 	.usernameParameter("userId")         // 아이디 파라미터명 설정
		// 	.passwordParameter("passwd")         //패스워드 파라미터명 설정
		// 	.loginProcessingUrl("/login_proc")   //로그인 form Action url 설정
		// 	//endregion
		//
		// 	// 로그인 성공후 핸들러
		// 	.successHandler(new AuthenticationSuccessHandler() {
		// 		@Override
		// 		public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
		// 			System.out.println("authentication" + authentication.getName());
		// 			response.sendRedirect("/");
		// 		}
		// 	})
		//
		// 	// 로그인 실패 후 핸들러
		// 	.failureHandler(new AuthenticationFailureHandler() {
		// 		@Override
		// 		public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
		// 			System.out.println("exception" + exception.getMessage());
		// 			response.sendRedirect("/login");
		// 		}
		// 	})
		// 	.permitAll();  //로그인페이지를 모든 사용자가 접근 가능하도록 설정
		//
		// //region logout
		// http
		// 	.logout()                                     //Post로 진행해야함
		// 	.logoutUrl("/logout")                         // 로그아웃 처리 url
		// 	.logoutSuccessUrl("/login")                  // 로그아웃 성공 후 이동페이지
		// 	.addLogoutHandler(new LogoutHandler() {      // 로그아웃 핸들러
		// 		@Override
		// 		public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
		// 			HttpSession session = request.getSession();
		// 			session.invalidate();
		// 		}
		// 	})
		// 	.logoutSuccessHandler(new LogoutSuccessHandler() {         // 로그아웃 성공 후 핸들러
		// 		@Override
		// 		public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
		// 			response.sendRedirect("/login");
		// 		}
		// 	})
		// 	.deleteCookies("JSESSIONID", "remember-me"); // 로그아웃 후 쿠키 삭제
		// // endregion
		//
		// //region rememberMe
		// http
		// 	.rememberMe()
		// 	.rememberMeParameter("remember")  // 기본 파라미터명은 remember-me
		// 	.tokenValiditySeconds(3600)  // 유지 시간 Default 는 14일
		// 	.alwaysRemember(false) // 리멤버 미 기능을 활성화하지 않아도 계속 실행할 것인지
		//
		// //endregion
		;

		http.sessionManagement()
			.sessionFixation().changeSessionId()  //  설정안해도 기본값  //none, migrateSession, newSession
			// .maximumSessions(1)  // 최대 허용 가능 세션 수,  -1 : 무제한
			// .maxSessionsPreventsLogin(false)  // 동시 로그인 차단함,  false : 기존 세션  만료 (default)
			// .expiredUrl("/expired")  // 세션이 만료된 경우 이동할 페이지
			/**
			 * SessionCreationPolicy.ALWAYS  : 스프링 시큐리티 항상 세션 생성
			 * SessionCreationPolicy.IF_REQUIRED  : 스프링 시큐리티가 필요시 생성(기본값)
			 * SessionCreationPolicy.NEVER  : 스프링 시큐리티가 생성하지 않지만 이미 존재하면 사용
			 * SessionCreationPolicy.STATELESS  : 스프링 시큐리티가 생성하지 않고 존재해도 사용하지 않음 (토큰)
			 * */
			// .sessionCreationPolicy(SessionCreationPolicy.NEVER);
		;
		return http.build();
	}

}
