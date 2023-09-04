package coid.security.springsecurity.aopSecurity;

import coid.security.springsecurity.dto.AccountDto;
import java.security.Principal;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AopSecurityController {

	@GetMapping("/preAuthorize")
	@PreAuthorize("hasRole('ROLE_USER') and #account.username == principal.username")
	public String preAuthorize(AccountDto account, Model model, Principal principal){
		model.addAttribute("method", "success @PreAuthorize");
		return "aop/method";
	}
}
