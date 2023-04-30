package coid.security.springsecurity.service;

import coid.security.springsecurity.dmain.Account;
import coid.security.springsecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service("userService")
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class UserServiceImpl implements UserService {

	private final UserRepository userRepository;

	@Override
	@Transactional
	public void createUser(Account account) {
		userRepository.save(account);
	}
}
