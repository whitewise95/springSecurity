# 6-8) 계층 권한 적용하기- RoleHierarchy
> 현재는 ADMIN, MANAGER, USER 권한을 전부 가져야 모든 리소스에 접근이 가능하지만 계층을 셋팅해 ADMIN 권한만 있어도 MANAGER 와 USER 권한까지 인증할 수 있도록 한다.  

![화면 캡처 2023-08-26 190509.jpg](..%2F..%2F..%2FDesktop%2F%ED%99%94%EB%A9%B4%20%EC%BA%A1%EC%B2%98%202023-08-26%20190509.jpg)

<br>
<br>
<br>

## RoleHierarchy Entity 생성
> Role 의 계층을 저장해줄 엔티티 생성
```java
@Entity
@Table(name = "ROLE_HIERARCHY")
@AllArgsConstructor
@NoArgsConstructor
@Data
@Builder
@ToString(exclude = {"parentName", "roleHierarchy"})
//@JsonIdentityInfo(generator = ObjectIdGenerators.IntSequenceGenerator.class)
public class RoleHierarchy implements Serializable {

	@Id
	@GeneratedValue
	private Long id;

	@Column(name = "child_name")
	private String childName;

	@ManyToOne(cascade = {CascadeType.ALL}, fetch = FetchType.LAZY)
	@JoinColumn(name = "parent_name", referencedColumnName = "child_name")
	private RoleHierarchy parentName;

	@OneToMany(mappedBy = "parentName", cascade = {CascadeType.ALL})
	private Set<RoleHierarchy> roleHierarchy = new HashSet<RoleHierarchy>();
}
```  

<br>
<br>

## RoleHierarchyRepository 생성
```java
@Repository
public interface RoleHierarchyRepository extends JpaRepository<RoleHierarchy, Long> {

	RoleHierarchy findByChildName(String roleName);
}
```

<br>
<br>

## RoleHierarchyService 생성
> DB에서 계층 데이터를 조회해 데이터를 계층구조로 만들 로직
```java
@Service
@RequiredArgsConstructor
public class RoleHierarchyService {

	private final RoleHierarchyRepository roleHierarchyRepository;

	@Transactional
	public String findAllHierarchy() {

		List<RoleHierarchy> rolesHierarchy = roleHierarchyRepository.findAll();

		Iterator<RoleHierarchy> itr = rolesHierarchy.iterator();
		StringBuffer concatedRoles = new StringBuffer();
		while (itr.hasNext()) {
			RoleHierarchy model = itr.next();
			if (model.getParentName() != null) {
				concatedRoles.append(model.getParentName().getChildName());
				concatedRoles.append(" > ");
				concatedRoles.append(model.getChildName());
				concatedRoles.append("\n");
			}
		}
		return concatedRoles.toString();

	}
}
```

<br>
<br>

## SecurityInitializer 생성
> 만들어준 계층 구조를 셋팅해주는 로직
```java
@Component
@RequiredArgsConstructor
public class SecurityInitializer implements ApplicationRunner {

	private final RoleHierarchyService roleHierarchyService;

	private final RoleHierarchyImpl roleHierarchy;

	@Override
	public void run(ApplicationArguments args) throws Exception {
		String allHierarchy = roleHierarchyService.findAllHierarchy();
		roleHierarchy.setHierarchy(allHierarchy);
	}
}
```

<br>
<br>

## SecurityConfig 수정
> 로직 수정 및 추가한다.

- 변경 전
```java
	@Bean
	public List<AccessDecisionVoter<?>> getAccessDecistionVoters() {
		return Arrays.asList(new RoleVoter());
	}
```

<br>


- 변경 후 
```java
	@Bean
	public List<AccessDecisionVoter<?>> getAccessDecistionVoters() {
		List<AccessDecisionVoter<? extends Object>> accessDecisionVoters = new ArrayList<>();
		accessDecisionVoters.add(new RoleVoter());
		return accessDecisionVoters;
	}
```


<br>



- 추가된 로직
```java
	@Bean
	public AccessDecisionVoter<? extends Object> roleVoter() {
		RoleHierarchyVoter roleHierarchyVoter = new RoleHierarchyVoter(roleHierarchy());
		return roleHierarchyVoter;
	}

	@Bean
	public RoleHierarchyImpl roleHierarchy() {
		RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
		return roleHierarchy;
	}
```



