package coid.security.springsecurity.repository;


import coid.security.springsecurity.dmain.AccessIp;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AccessIpRepository extends JpaRepository<AccessIp, Long> {

	AccessIp findByIpAddress(String IpAddress);

}
