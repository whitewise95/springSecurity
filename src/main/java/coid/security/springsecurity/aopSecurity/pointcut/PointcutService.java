package coid.security.springsecurity.aopSecurity.pointcut;

import org.springframework.stereotype.Service;

@Service
public class PointcutService {

    public void pointcutSecured() {
        System.out.println("pointcutSecured");
    }

    public void notSecured() {
        System.out.println("notSecured");
    }
}
