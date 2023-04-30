package coid.security.springsecurity.security.service;

import coid.security.springsecurity.dmain.Account;
import coid.security.springsecurity.repository.UserRepository;
import java.util.ArrayList;
import java.util.List;
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
			throw new UsernameNotFoundException("UsernameNotFoundException");
		}

		List<GrantedAuthority> roles = new ArrayList<>();
		roles.add(new SimpleGrantedAuthority(account.getRole()));

		AccountContext accountContext = new AccountContext(account, roles);
		return accountContext;
	}
}
