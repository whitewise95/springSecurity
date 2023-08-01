package coid.security.springsecurity.repository;


import coid.security.springsecurity.dmain.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {

    Role findByRoleName(String name);

    @Override
    void delete(Role role);

}
