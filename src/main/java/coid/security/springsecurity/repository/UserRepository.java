package coid.security.springsecurity.repository;

import coid.security.springsecurity.dmain.Account;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<Account, Long> {

	Account findByUsername(String username);
}
