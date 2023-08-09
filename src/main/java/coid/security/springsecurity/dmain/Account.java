package coid.security.springsecurity.dmain;

import javax.persistence.*;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.*;

import java.util.HashSet;
import java.util.Set;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class Account {

	@Id
	@GeneratedValue
	private Long id;
	private String username;
	private String password;
	private String email;
	private Integer age;

	@JsonIgnore
	@ManyToMany(fetch = FetchType.LAZY, cascade={CascadeType.ALL})
	@JoinTable(name = "account_roles", joinColumns = { @JoinColumn(name = "account_id") }, inverseJoinColumns = {
			@JoinColumn(name = "role_id") })
	private Set<Role> userRoles = new HashSet<>();
}
