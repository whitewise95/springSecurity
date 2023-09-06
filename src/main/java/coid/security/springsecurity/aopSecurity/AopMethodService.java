package coid.security.springsecurity.aopSecurity;


import org.springframework.stereotype.Service;

@Service
public class AopMethodService {

	public void methodSecured() {
		System.out.println("methodSecured");
	}

}
