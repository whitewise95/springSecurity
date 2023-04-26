package coid.security.springsecurity.controller;

import javax.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityController {

	@GetMapping("/")
	public String index(HttpSession session) {

		//방법1
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

		//방법2
		SecurityContext attribute = (SecurityContext) session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
		Authentication authentication1 = attribute.getAuthentication();
		return "home";
	}

	@GetMapping("/thread")
	public String thread() {
		new Thread(

			new Runnable() {
				@Override
				public void run() {
					Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
				}
			}

		).start();

		return "thread";
	}

}
