package coid.security.springsecurity.security.service;

import coid.security.springsecurity.dmain.Account;
import coid.security.springsecurity.repository.UserRepository;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

	private final UserRepository userRepository;

	public CustomUserDetailsService(UserRepository userRepository) {
		this.userRepository = userRepository;
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

		Account account = userRepository.findByUsername(username);
		if (account == null) {
			if (userRepository.countByUsername(username) == 0) {
				throw new UsernameNotFoundException("No user found with username: " + username);
			}
		}
		List<GrantedAuthority> collect = account.getUserRoles()
				.stream()
				.map(userRole -> userRole.getRoleName())
				.collect(Collectors.toSet())
				.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());

		return new AccountContext(account, collect);
	}
}
