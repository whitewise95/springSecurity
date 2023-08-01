package coid.security.springsecurity.dto;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class AccountDto {

	private Long id;
	private String username;
	private String password;
	private String email;
	private String age;
	private List<String> roles;
}
