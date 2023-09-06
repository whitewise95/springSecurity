package coid.security.springsecurity.security.factory;

import coid.security.springsecurity.security.service.SecurityResourceService;
import java.util.LinkedHashMap;
import java.util.List;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.security.access.ConfigAttribute;

public class MethodResourceFactoryBean implements FactoryBean<LinkedHashMap<String, List<ConfigAttribute>>> {

	private SecurityResourceService securityResourceService;
	private LinkedHashMap<String, List<ConfigAttribute>> resourceMap;

	public void setSecurityResourceService(SecurityResourceService securityResourceService) {
		this.securityResourceService = securityResourceService;
	}

	@Override
	public LinkedHashMap<String, List<ConfigAttribute>> getObject() {
		if (resourceMap == null) {
			init();
		}
		return resourceMap;
	}

	private void init() {
		resourceMap = securityResourceService.getMethodResourceList();
	}

	@Override
	public Class<?> getObjectType() {
		return LinkedHashMap.class;
	}

	@Override
	public boolean isSingleton() {
		return FactoryBean.super.isSingleton();
	}
}