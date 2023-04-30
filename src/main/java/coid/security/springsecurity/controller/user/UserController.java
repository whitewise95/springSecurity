package coid.security.springsecurity.controller.user;


import coid.security.springsecurity.dmain.Account;
import coid.security.springsecurity.dto.AccountDto;
import coid.security.springsecurity.dto.AccountDtoMapper;
import coid.security.springsecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@Controller
@RequiredArgsConstructor
public class UserController {

	private final UserService userService;
	private final PasswordEncoder passwordEncoder;

	@GetMapping(value = "/mypage")
	public String myPage() throws Exception {
		return "/user/mypage";
	}

	@GetMapping("/users")
	public String createUserView() {
		return "user/login/register";
	}

	@PostMapping("/users")
	public String createUser(AccountDto accountDto) {

		Account account = AccountDtoMapper.INSTANCE.create(accountDto);
		account.setPassword(passwordEncoder.encode(account.getPassword()));
		userService.createUser(account);
		return "redirect:/";
	}
}
