package coid.security.springsecurity.security.coreSpringSecurity.config;

import coid.security.springsecurity.repository.AccessIpRepository;
import coid.security.springsecurity.repository.ResourcesRepository;
import coid.security.springsecurity.security.service.SecurityResourceService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AppConfig {

    @Bean
    public SecurityResourceService securityResourceService(ResourcesRepository resourcesRepository, AccessIpRepository accessIpRepository ){
        SecurityResourceService securityResourceService = new SecurityResourceService(resourcesRepository, accessIpRepository);
        return securityResourceService;
    }
}
