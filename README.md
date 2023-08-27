# 6-9) 아이피 접속 제한하기 - CustomIpAddressVoter  
> 특정한 ip만 접근이 가능하도록 심의하는 Voter를 추가한다.
> 허용된 IP 이면 ACCESS_GRANTER 가 아닌 ACCESS_ABSTAIN 을 리턴해서 추가 심의를 진행
> 허용된 IP가 아니면 ACCESS_DENIED 를 리턴하지 않고 즉시 예외 발생하여 최종 자원에 접근 거부
![img.png](img.png)

<br>
<br>

## AccessIp Entity 생성
> IP 를 저장할 엔티티
```java
@Entity
@Table(name = "ACCESS_IP")
@Data
@EqualsAndHashCode(of = "id")
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AccessIp implements Serializable {

	@Id
	@GeneratedValue
	@Column(name = "IP_ID", unique = true, nullable = false)
	private Long id;

	@Column(name = "IP_ADDRESS", nullable = false)
	private String ipAddress;

}
```

<br>
<br>



## AccessIpRepository 생성
```java
@Repository
public interface AccessIpRepository extends JpaRepository<AccessIp, Long> {

	AccessIp findByIpAddress(String IpAddress);

}
```

<br>
<br>


## SetupDataLoader 클래스 로직추가 
- 해당 메소드를 추가한다.
```java
	private void setupAccessIpData() {
		AccessIp byIpAddress = accessIpRepository.findByIpAddress("127.0.0.1");
		if (byIpAddress == null) {
			AccessIp accessIp = AccessIp.builder()
										.ipAddress("127.0.0.1")
										.build();
			accessIpRepository.save(accessIp);
		}
	}
```

<br>
<br>


- 기존 setupSecurityResources 메소드에 setupAccessIpData() 를 추가한다.
```java
	public void setupSecurityResources(){
	    setupAccessIpData();
        ... 기존로직
	}
```


<br>
<br>


## SecurityResourceService 로직 추가
> getAccessIpList 메소드를 추가해 DB에 저장되어있는 IP를 리턴한다.
```java
public class SecurityResourceService {

    private ResourcesRepository resourcesRepository;
    private AccessIpRepository accessIpRepository;

    public SecurityResourceService(ResourcesRepository resourcesRepository, AccessIpRepository accessIpRepository) {
        this.resourcesRepository = resourcesRepository;
        this.accessIpRepository = accessIpRepository;
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

	public List<String> getAccessIpList() {
        return accessIpRepository.findAll().stream().map(AccessIp::getIpAddress).collect(Collectors.toList());
    }
}
```

<br>
<br>


## AccessDecisionVoter<Object> 를 상속한 클래스 생성
> 실제로 ip 허용과 미허용을 구분하는 로직을 담당
```java
public class IpAddressVoter implements AccessDecisionVoter<Object> {

	private SecurityResourceService securityResourceService;

	public IpAddressVoter(SecurityResourceService securityResourceService) {
		this.securityResourceService = securityResourceService;
	}

	@Override
	public boolean supports(ConfigAttribute attribute) {
		return true;
	}

	@Override
	public boolean supports(Class<?> clazz) {
		return true;
	}

	@Override
	public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> attributes) {
		WebAuthenticationDetails details = (WebAuthenticationDetails) authentication.getDetails();
		String remoteAddress = details.getRemoteAddress();

		List<String> accessIpList = securityResourceService.getAccessIpList();

		int result = ACCESS_DENIED;

		for (String ipAddress : accessIpList) {
			if (ipAddress.equals(remoteAddress)) {
				result = ACCESS_ABSTAIN;
				break;
			}
		}

		if (result == ACCESS_DENIED) {
			throw new AccessDeniedException("Invalid IpAddress");
		}

		return result;
	}
}
```

<br>
<br>



## SecurityConfig 로직 추가

- 기존로직
```java
	@Bean
	public List<AccessDecisionVoter<?>> getAccessDecistionVoters() {
		List<AccessDecisionVoter<? extends Object>> accessDecisionVoters = new ArrayList<>();
		accessDecisionVoters.add(roleVoter());
		return accessDecisionVoters;
	}
```

<br>
<br>


- 변경로직
> 반드시 `roleVoter()` 보다 먼저 실행되어야한다.
```java
	@Bean
	public List<AccessDecisionVoter<?>> getAccessDecistionVoters() {
		List<AccessDecisionVoter<? extends Object>> accessDecisionVoters = new ArrayList<>();
		accessDecisionVoters.add(new IpAddressVoter(securityResourceService));
		accessDecisionVoters.add(roleVoter());
		return accessDecisionVoters;
	}
```

<br>
<br>


## AjaxLoginProcessingFilter 로직 추가
> 로그인한 회원의 details를 저장한다.
```java
public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {

	@Autowired
	private ObjectMapper objectMapper;

	public AjaxLoginProcessingFilter() {
		super(new AntPathRequestMatcher("/api/login"));
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

		if (isAjax(request)) {
			throw new IllegalStateException("Authentication is not supported");
		}

		AccountDto accountDto = objectMapper.readValue(request.getReader(), AccountDto.class);
		if (StringUtils.isEmpty(accountDto.getUsername()) || StringUtils.isEmpty(accountDto.getPassword())) {
			throw new IllegalArgumentException("Username or Password is empty");
		}

		AjaxAuthenticationToken ajaxAuthenticationToken = new AjaxAuthenticationToken(accountDto.getUsername(), accountDto.getPassword());
		setDetails(request, ajaxAuthenticationToken);
		return getAuthenticationManager().authenticate(ajaxAuthenticationToken);
	}

	private boolean isAjax(HttpServletRequest request) {
		if ("XMLHttpRequest".equals(request.getHeader("X-RequestedWith"))) {
			return true;
		}

		return false;
	}

	protected void setDetails(HttpServletRequest request, AjaxAuthenticationToken ajaxAuthenticationToken) {
		ajaxAuthenticationToken.setDetails(this.authenticationDetailsSource.buildDetails(request));
	}
}
```



