package coid.security.springsecurity.security.configs;

import coid.security.springsecurity.security.factory.MethodResourceFactoryBean;
import coid.security.springsecurity.security.service.SecurityResourceService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.method.MapBasedMethodSecurityMetadataSource;
import org.springframework.security.access.method.MethodSecurityMetadataSource;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;

@Configuration
@RequiredArgsConstructor
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class MethodSecurityConfig extends GlobalMethodSecurityConfiguration {

	private final SecurityResourceService securityResourceService;


	@Override
	protected MethodSecurityMetadataSource customMethodSecurityMetadataSource() {
		return mapBasedMethodSecurityMetadataSource();
	}

	@Bean
	public MapBasedMethodSecurityMetadataSource mapBasedMethodSecurityMetadataSource() {
		return new MapBasedMethodSecurityMetadataSource(methodResourcesMapFactoryBean().getObject());
	}

	@Bean
	public MethodResourceFactoryBean methodResourcesMapFactoryBean() {
		MethodResourceFactoryBean methodResourceFactoryBean = new MethodResourceFactoryBean();
		methodResourceFactoryBean.setSecurityResourceService(securityResourceService);
		return methodResourceFactoryBean;
	}
}
