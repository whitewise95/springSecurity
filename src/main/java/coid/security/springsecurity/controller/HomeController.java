package coid.security.springsecurity.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

	@GetMapping("/")
	public String home() {
		return "home";
	}

	@GetMapping("/user")
	public String user() {
		return "user";
	}

	@GetMapping("/admin/pay")
	public String adminPay() {
		return "adminPay";
	}

	@GetMapping("/admin/**")
	public String admin() {
		return "admin";
	}

	@GetMapping("/denied")
	public String denied() {
		return "denied";
	}

	@GetMapping("/login")
	public String login() {
		return "login";
	}
}
