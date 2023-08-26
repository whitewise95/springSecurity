package coid.security.springsecurity.repository;

import coid.security.springsecurity.dmain.RoleHierarchy;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleHierarchyRepository extends JpaRepository<RoleHierarchy, Long> {

	RoleHierarchy findByChildName(String roleName);
}
