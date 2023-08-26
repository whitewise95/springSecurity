package coid.security.springsecurity.security.metadatasource;

import coid.security.springsecurity.security.service.SecurityResourceService;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.RequestMatcher;

public class UrlFilterInvocationSecurityMetaDatsSource implements FilterInvocationSecurityMetadataSource {

	private LinkedHashMap<RequestMatcher, List<ConfigAttribute>> requestMap = new LinkedHashMap<>();

	private SecurityResourceService securityResourceService;


	public UrlFilterInvocationSecurityMetaDatsSource(LinkedHashMap<RequestMatcher, List<ConfigAttribute>> requestMap, SecurityResourceService securityResourceService) {
		this.securityResourceService = securityResourceService;
		this.requestMap = requestMap;
	}

	@Override
	public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {

		HttpServletRequest request = ((FilterInvocation) object).getRequest();

		if (requestMap != null) {
			for (Map.Entry<RequestMatcher, List<ConfigAttribute>> entry : requestMap.entrySet()) {
				RequestMatcher matcher = entry.getKey();
				if (matcher.matches(request)) {
					return entry.getValue();
				}
			}
		}

		return null;
	}

	@Override
	public Collection<ConfigAttribute> getAllConfigAttributes() {
		Set<ConfigAttribute> allAttributes = new HashSet<>();

		for (Map.Entry<RequestMatcher, List<ConfigAttribute>> entry : requestMap.entrySet()) {
			allAttributes.addAll(entry.getValue());
		}

		return allAttributes;
	}

	@Override
	public boolean supports(Class<?> clazz) {
		return FilterInvocation.class.isAssignableFrom(clazz);
	}

	public void reload() {
		LinkedHashMap<RequestMatcher, List<ConfigAttribute>> resourceList = securityResourceService.getResourceList();
		Iterator<Map.Entry<RequestMatcher, List<ConfigAttribute>>> iterator = resourceList.entrySet().iterator();
		requestMap.clear();

		while (iterator.hasNext()) {
			Map.Entry<RequestMatcher, List<ConfigAttribute>> entry = iterator.next();
			requestMap.put(entry.getKey(), entry.getValue());
		}

	}
}
