package coid.security.springsecurity.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

	@GetMapping("/")
	public String home() {
		return "home";
	}

	@GetMapping("loginPage")
	public String loginPage() {
		return "loginPage";
	}
}
