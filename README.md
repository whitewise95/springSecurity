# 6-5) 웹 기반 인가처리 DB 연동 - FilterInvocationSecurityMetadataSource (2)

## SecurityResourceService 생성
> FilterInvocationSecurityMetadataSource 구현 클래스에서 필요한 LinkedHashMap<RequestMatcher, List<ConfigAttribute>> 객체를 생성하는 로직을 SecurityResourceService에서 처리한다.
```java
public class SecurityResourceService {

    private ResourcesRepository resourcesRepository;

    public SecurityResourceService(ResourcesRepository resourcesRepository) {
        this.resourcesRepository = resourcesRepository;
    }

    public LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getResourceList() {
        LinkedHashMap<RequestMatcher, List<ConfigAttribute>> result = new LinkedHashMap<>();

        List<Resources> resourcesList = resourcesRepository.findAllResources();
        resourcesList.forEach(x -> {
            List<ConfigAttribute> configAttributeList = new ArrayList<>();
            x.getRoleSet().forEach(role -> configAttributeList.add(new SecurityConfig(role.getRoleName())));
            result.put(new AntPathRequestMatcher(x.getResourceName()), configAttributeList);
        });

        return result;
    }
}
```

<br>
<br>


### AppConfig 생성 
> SecurityResourceService를 Bean으로 등록하기위해 `@Configuration` 를 사용할 AppConfig.java 생성
```java
@Configuration
public class AppConfig {

    @Bean
    public SecurityResourceService securityResourceService(ResourcesRepository resourcesRepository){
        SecurityResourceService securityResourceService = new SecurityResourceService(resourcesRepository);
        return securityResourceService;
    }
}
```


<br>
<br>



## UrlResourceMapFactoryBean 클래스 생성
> 해당 클래스는  FactoryBean<LinkedHashMap<RequestMatcher, List<ConfigAttribute>>> 를 구현하기 위해 생성

```java
public class UrlResourceMapFactoryBean implements FactoryBean<LinkedHashMap<RequestMatcher, List<ConfigAttribute>>> {

    private SecurityResourceService securityResourceService;
    private LinkedHashMap<RequestMatcher, List<ConfigAttribute>> resourceMap;

    public void setSecurityResourceService(SecurityResourceService securityResourceService) {
        this.securityResourceService = securityResourceService;
    }

    @Override
    public LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getObject() throws Exception {
        if (resourceMap == null) {
            init();
        }
        return resourceMap;
    }

    private void init(){
        resourceMap = securityResourceService.getResourceList();
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
```

<br>
<br>



## SecurityConfig에 로직 추가
```java
	@Bean
	public FilterInvocationSecurityMetadataSource urlFilterInvocationSecurityMetadatasource() throws Exception {
		return new UrlFilterInvocationSecurityMetadatsSource(urlResourceMapFactoryBean().getObject());
	}

	private UrlResourceMapFactoryBean urlResourceMapFactoryBean() {
		UrlResourceMapFactoryBean resourceMapFactoryBean = new UrlResourceMapFactoryBean();
		resourceMapFactoryBean.setSecurityResourceService(securityResourceService);
		return resourceMapFactoryBean;
	}
```

<br>


- 전체로직
```java
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@Order(1)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	private final UserDetailsService userDetailsService;
	private final AuthenticationDetailsSource authenticationDetailsSource;
	private final CustomAuthenticationSuccessHandler authenticationSuccessHandler;
	private final CustomAuthenticationFailureHandler authenticationFailureHandler;
	private final SecurityResourceService securityResourceService;


	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.authorizeRequests()
			.antMatchers("/", "/users", "/login*").permitAll()
			.antMatchers("/mypage").hasRole("USER")
			.antMatchers("/messages").hasRole("MANAGER")
			.antMatchers("/config").hasRole("ADMIN")
			.anyRequest().authenticated()
			.and()
			.exceptionHandling()  // 추가
			.accessDeniedHandler(accessDeniedHandler()) // 추가
			.and()
			.formLogin()
			.loginPage("/login")
			.loginProcessingUrl("/login_proc") // login form의 action과 동일한 url로 유지해줘야한다.
			.authenticationDetailsSource(authenticationDetailsSource)
			.defaultSuccessUrl("/")
			.successHandler(authenticationSuccessHandler)
			.failureHandler(authenticationFailureHandler)
			.permitAll();

		http
			.addFilterBefore(customFilterSecurityInterceptor(), FilterSecurityInterceptor.class);
	}

	private AccessDeniedHandler accessDeniedHandler() { // 추가
		CustomAccessDeniedHandler deniedHandler = new CustomAccessDeniedHandler();
		deniedHandler.setErrorPage("/denied");
		return deniedHandler;
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(authenticationProvider());
	}

	@Bean
	public AuthenticationProvider authenticationProvider() {
		return new CustomAuthenticationProvider(userDetailsService, passwordEncoder());
	}

	@Override
	public void configure(WebSecurity web) {
		web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
	}

	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

	@Bean
	public FilterSecurityInterceptor customFilterSecurityInterceptor() throws Exception {
		FilterSecurityInterceptor filterSecurityInterceptor = new FilterSecurityInterceptor();
		filterSecurityInterceptor.setSecurityMetadataSource(urlFilterInvocationSecurityMetadatasource());
		filterSecurityInterceptor.setAccessDecisionManager(affirmativeBased());
		filterSecurityInterceptor.setAuthenticationManager(authenticationManagerBean());
		return filterSecurityInterceptor;
	}

	@Bean
	public AccessDecisionManager affirmativeBased() {
		AffirmativeBased affirmativeBased = new AffirmativeBased(getAccessDecistionVoters());
		return affirmativeBased;
	}

	@Bean
	public List<AccessDecisionVoter<?>> getAccessDecistionVoters() {
		return Arrays.asList(new RoleVoter());
	}

	@Bean
	public FilterInvocationSecurityMetadataSource urlFilterInvocationSecurityMetadatasource() throws Exception {
		return new UrlFilterInvocationSecurityMetadatsSource(urlResourceMapFactoryBean().getObject());
	}

	private UrlResourceMapFactoryBean urlResourceMapFactoryBean() {
		UrlResourceMapFactoryBean resourceMapFactoryBean = new UrlResourceMapFactoryBean();
		resourceMapFactoryBean.setSecurityResourceService(securityResourceService);
		return resourceMapFactoryBean;
	}
}
```



