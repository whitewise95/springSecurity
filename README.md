# 7-5) AOP Method 기반 DB 연동 - MapBasedSecurityMetadataSource (2)

## GlobalMethodSecurityConfiguration 상속받는 클래스 생성
> Map 기반으로 DB와 연동하기위한 GlobalMethodSecurityConfiguration 를 상속받는 클래스 생성한다.
> SecurityConfig 에서 `@EnableGlobalMethodSecurity` 는 삭제하고 생성한 클래스에서 설정해준다.


```java
@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class MethodSecurityConfig extends GlobalMethodSecurityConfiguration {

	@Override
	protected MethodSecurityMetadataSource customMethodSecurityMetadataSource() {
		return new MapBasedMethodSecurityMetadataSource();
	}
}
```