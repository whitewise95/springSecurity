package coid.security.springsecurity.dmain;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
public class Account {

	@Id
	@GeneratedValue
	private Long id;
	private String username;
	private String password;
	private String email;
	private String age;
	private String role;
}
