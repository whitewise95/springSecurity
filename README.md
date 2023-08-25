# 6-6) 웹 기반 인가처리 실시간 반영하기
> 권한을 수정하면 해당 권한이 바로 반영이 가능해야한다.


## UrlFilterInvocationSecurityMetaDatsSource에 reload() 추가
```java

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
```

## SecurityConfig 수정
> 생성자 인자로 securityResourceService를 추가한다.
```java
	@Bean
    public FilterInvocationSecurityMetadataSource urlFilterInvocationSecurityMetadatasource() throws Exception {
	    return new UrlFilterInvocationSecurityMetaDatsSource(urlResourceMapFactoryBean().getObject(), securityResourceService);
	}
```

## ResourcesController의 create 메소드와 remove 메소드에 reload 메소드를 추가한다.
```java
    private final UrlFilterInvocationSecurityMetaDatsSource urlFilterInvocationSecurityMetaDatsSource;

    @PostMapping(value = "/admin/resources")
    public String createResources(ResourcesDto resourcesDto) throws Exception {
        ModelMapper modelMapper = new ModelMapper();
        Role role = roleRepository.findByRoleName(resourcesDto.getRoleName());
        Set<Role> roles = new HashSet<>();
        roles.add(role);
        Resources resources = modelMapper.map(resourcesDto, Resources.class);
        resources.setRoleSet(roles);
    
        resourcesService.createResources(resources);
        urlFilterInvocationSecurityMetaDatsSource.reload();
        return "redirect:/admin/resources";
	}

    @GetMapping(value = "/admin/resources/delete/{id}")
    public String removeResources(@PathVariable String id, Model model) throws Exception {
        Resources resources = resourcesService.getResources(Long.valueOf(id));
        resourcesService.deleteResources(Long.valueOf(id));
        urlFilterInvocationSecurityMetaDatsSource.reload();
        return "redirect:/admin/resources";
    }
```