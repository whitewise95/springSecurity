package coid.security.springsecurity.security.service;

import coid.security.springsecurity.dmain.Account;
import java.util.Collection;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

public class AccountContext extends User {

	private final Account account;

	public AccountContext(Account account, Collection<? extends GrantedAuthority> authorities) {
		super(account.getUsername(), account.getPassword(), authorities);
		this.account = account;
	}

	public Account getAccount() {
		return account;
	}
}
