# 7-7) AOP Method 기반 DB 연동 - ProtectPointcutPostProcessor

## SetupDataLoader.setupSecurityResources() 메소드에 DB저장 로직 추가
```java
createResourceIfNotFound("execution(* coid.security.springsecurity.aopSecurity.pointcut.*Service.pointcut*(..))", "", roles1, "pointcut");
```

- 전체메소드 로직
```java
	public void setupSecurityResources() {
		setupAccessIpData();

		Set<Role> roles = new HashSet<>();
		Role adminRole = createRoleIfNotFound("ROLE_ADMIN", "관리자");
		roles.add(adminRole);
		createResourceIfNotFound("/admin/**", "", roles, "url");
		Account account = createUserIfNotFound("admin", "pass", "admin@gmail.com", 10, roles);

		Set<Role> roles1 = new HashSet<>();


		Role managerRole = createRoleIfNotFound("ROLE_MANAGER", "매니저");
		roles1.add(managerRole);

		Set<Role> roles3 = new HashSet<>();

		Role childRole1 = createRoleIfNotFound("ROLE_USER", "회원");
		roles3.add(childRole1);
		createResourceIfNotFound("/users/**", "", roles3, "url");
		createUserIfNotFound("user", "pass", "user@gmail.com", 30, roles3);
		createRoleHierarchyIfNotFound(childRole1, managerRole);
		createRoleHierarchyIfNotFound(managerRole, adminRole);

		createResourceIfNotFound("coid.security.springsecurity.aopSecurity.AopMethodService.methodSecured", "", roles3, "method");
		// createResourceIfNotFound("coid.security.springsecurity.aopsecurity.method.AopMethodService.innerCallMethodTest", "", roles1, "method");
		 createResourceIfNotFound("execution(* coid.security.springsecurity.aopSecurity.pointcut.*Service.pointcut*(..))", "", roles1, "pointcut");
		// createUserIfNotFound("manager", "pass", "manager@gmail.com", 20, roles1);

	}
```

## method.html, home.html 에 href 추가
```html
 <a th:href="@{/pointcutSecured}" style="margin:5px;" class="nav-link text-primary">포인트컷보안</a>
```

- 전체로직
```html
<!DOCTYPE html>
<html lang="ko" xmlns:th="http://www.thymeleaf.org">
<head th:replace="layout/header::userHead"></head>
<body>
<div th:replace="layout/top::header"></div>
<div class="container">
  <div class="row align-items-start">
    <nav class="col-md-2 d-none d-md-block bg-light sidebar">
      <div class="sidebar-sticky">
        <ul class="nav flex-column">
          <li class="nav-item">
            <div style="padding-top:10px;" class="nav flex-column nav-pills" aria-orientation="vertical">
              <a th:href="@{/}" style="margin:5px;" class="nav-link active">대시보드</a>
              <a th:href="@{/mypage}" style="margin:5px;" class="nav-link text-primary">마이페이지</a>
              <a th:href="@{/messages}" style="margin:5px;" class="nav-link text-primary">메시지</a>
              <a th:href="@{/config}" style="margin:5px;" class="nav-link text-primary">환경설정</a>
              <a th:href="@{/preAuthorize(username='user')}" style="margin:5px;" class="nav-link text-primary">@메소드보안</a>
              <a th:href="@{/methodSecured}" style="" class="nav-link text-primary">메소드보안</a>
              <a th:href="@{/pointcutSecured}" style="margin:5px;" class="nav-link text-primary">포인트컷보안</a>
            </div>
          </li>
        </ul>
      </div>
    </nav>
    <div style="padding-top:50px;"  class="col">
      <div class="container text-center">
        <h1 class="text-primary" th:text="${method}">Method</h1>
      </div>
    </div>
  </div>
  <div th:replace="layout/footer::footer"></div>
</body>
</html>
```

##  AopSecurityController에 로직추가 및 PointcutService 생성
- AopSecurityController
```java
	@GetMapping("/pointcutSecured")
	public String pointcutSecured(Model model){
		pointcutService.notSecured();
		pointcutService.pointcutSecured();
		model.addAttribute("method", "Success MethodSecured");
		return "aop/method";
	}
```

- PointcutService 생성
```html
@Service
public class PointcutService {

    public void pointcutSecured() {
        System.out.println("pointcutSecured");
    }

    public void notSecured() {
        System.out.println("notSecured");
    }
}
```

## MethodSecurityConfig 클래스에 로직추가
```java
    @Bean
    public MethodResourceFactoryBean pointcutResourcesMapFactoryBean() {
        MethodResourceFactoryBean methodResourceFactoryBean = new MethodResourceFactoryBean();
        methodResourceFactoryBean.setSecurityResourceService(securityResourceService);
        methodResourceFactoryBean.setResourceType("pointcut");
        return methodResourceFactoryBean;
    }

    @Bean
    public ProtectPointcutPostProcessor protectPointcutPostProcessor() {
        ProtectPointcutPostProcessor protectPointcutPostProcessor = new ProtectPointcutPostProcessor(mapBasedMethodSecurityMetadataSource());
        protectPointcutPostProcessor.setPointcutMap(pointcutResourcesMapFactoryBean().getObject());
        return protectPointcutPostProcessor;
    }
```

- 전체로직
```java
package coid.security.springsecurity.security.configs;

import coid.security.springsecurity.security.factory.MethodResourceFactoryBean;
import coid.security.springsecurity.security.processor.ProtectPointcutPostProcessor;
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
        methodResourceFactoryBean.setResourceType("method");
        return methodResourceFactoryBean;
    }

    @Bean
    public MethodResourceFactoryBean pointcutResourcesMapFactoryBean() {
        MethodResourceFactoryBean methodResourceFactoryBean = new MethodResourceFactoryBean();
        methodResourceFactoryBean.setSecurityResourceService(securityResourceService);
        methodResourceFactoryBean.setResourceType("pointcut");
        return methodResourceFactoryBean;
    }

    @Bean
    public ProtectPointcutPostProcessor protectPointcutPostProcessor() {
        ProtectPointcutPostProcessor protectPointcutPostProcessor = new ProtectPointcutPostProcessor(mapBasedMethodSecurityMetadataSource());
        protectPointcutPostProcessor.setPointcutMap(pointcutResourcesMapFactoryBean().getObject());
        return protectPointcutPostProcessor;
    }
}
```

##  MethodResourceFactoryBean 클래스에 로직 수정
```java
package coid.security.springsecurity.security.factory;

import coid.security.springsecurity.security.service.SecurityResourceService;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.security.access.ConfigAttribute;

import java.util.LinkedHashMap;
import java.util.List;

public class MethodResourceFactoryBean implements FactoryBean<LinkedHashMap<String, List<ConfigAttribute>>> {

    private SecurityResourceService securityResourceService;
    private String resourceType;
    private LinkedHashMap<String, List<ConfigAttribute>> resourceMap;

    public void setSecurityResourceService(SecurityResourceService securityResourceService) {
        this.securityResourceService = securityResourceService;
    }

    public void setResourceType(String resourceType) {
        this.resourceType = resourceType;
    }

    @Override
    public LinkedHashMap<String, List<ConfigAttribute>> getObject() {
        if (resourceMap == null) {
            init();
        }
        return resourceMap;
    }

    private void init() {
        if ("method".equals(resourceType)) {
            resourceMap = securityResourceService.getMethodResourceList();
        } else if ("pointcut".equals(resourceType)) {
            resourceMap = securityResourceService.getPointcutResourceList();
        }
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

## BeanPostProcessor 를 구현하는 클래스 생성
```java
package coid.security.springsecurity.security.processor;


import lombok.extern.slf4j.Slf4j;
import org.aspectj.weaver.tools.PointcutExpression;
import org.aspectj.weaver.tools.PointcutParser;
import org.aspectj.weaver.tools.PointcutPrimitive;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.method.MapBasedMethodSecurityMetadataSource;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.lang.reflect.Method;
import java.util.*;

@Slf4j
public class ProtectPointcutPostProcessor implements BeanPostProcessor {

    private final Map<String, List<ConfigAttribute>> pointcutMap = new LinkedHashMap<String, List<ConfigAttribute>>();
    private final MapBasedMethodSecurityMetadataSource mapBasedMethodSecurityMetadataSource;
    private final Set<PointcutExpression> pointCutExpressions = new LinkedHashSet<>();
    private final PointcutParser parser;
    private final Set<String> processedBeans = new HashSet<>();

    public ProtectPointcutPostProcessor(MapBasedMethodSecurityMetadataSource mapBasedMethodSecurityMetadataSource) {
        Assert.notNull(mapBasedMethodSecurityMetadataSource, "MapBasedMethodSecurityMetadataSource to populate is required");
        this.mapBasedMethodSecurityMetadataSource = mapBasedMethodSecurityMetadataSource;

        Set<PointcutPrimitive> supportedPrimitives = new HashSet<>(3);
        supportedPrimitives.add(PointcutPrimitive.EXECUTION);
        supportedPrimitives.add(PointcutPrimitive.ARGS);
        supportedPrimitives.add(PointcutPrimitive.REFERENCE);
        parser = PointcutParser.getPointcutParserSupportingSpecifiedPrimitivesAndUsingContextClassloaderForResolution(supportedPrimitives);
    }

    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        return bean;
    }

    public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {

        if (processedBeans.contains(beanName)) {
            return bean;
        }

        synchronized (processedBeans) {
            if (processedBeans.contains(beanName)) {
                return bean;
            }

            Method[] methods;
            try {
                methods = bean.getClass().getMethods();
            } catch (Exception e) {
                throw new IllegalStateException(e.getMessage());
            }

            for (Method method : methods) {
                for (PointcutExpression expression : pointCutExpressions) {
                    if (attemptMatch(bean.getClass(), method, expression, beanName)) {
                        break;
                    }
                }
            }

            processedBeans.add(beanName);
        }

        return bean;
    }

    /**
     * 설정클래스에서 람다 형식으로 선언된 빈이 존재할 경우 에러가 발생하여 스프링 빈과 동일한 클래스를 생성하여 약간 수정함
     * 아직 AspectJ 라이브러리에서 Fix 하지 못한 것으로 판단되지만 다른 원인이 존재하는지 계속 살펴보도록 함
     */
    private boolean attemptMatch(Class<?> targetClass, Method method, PointcutExpression expression, String beanName) {

        boolean matches;
        try {
            matches = expression.matchesMethodExecution(method).alwaysMatches();
            if (matches) {
                List<ConfigAttribute> attr = pointcutMap.get(expression.getPointcutExpression());

                if (log.isDebugEnabled()) {
                    log.debug("AspectJ pointcut expression '"
                            + expression.getPointcutExpression() + "' matches target class '"
                            + targetClass.getName() + "' (bean ID '" + beanName
                            + "') for method '" + method
                            + "'; registering security configuration attribute '" + attr
                            + "'");
                }

                mapBasedMethodSecurityMetadataSource.addSecureMethod(targetClass, method, attr);
            }
            return matches;

        } catch (Exception e) {
            matches = false;
        }
        return matches;
    }

    public void setPointcutMap(Map<String, List<ConfigAttribute>> map) {
        Assert.notEmpty(map, "configAttributes cannot be empty");
        for (String expression : map.keySet()) {
            List<ConfigAttribute> value = map.get(expression);
            addPointcut(expression, value);
        }
    }

    private void addPointcut(String pointcutExpression, List<ConfigAttribute> definition) {
        Assert.hasText(pointcutExpression, "An AspectJ pointcut expression is required");
        Assert.notNull(definition, "A List of ConfigAttributes is required");
        pointcutExpression = replaceBooleanOperators(pointcutExpression);
        pointcutMap.put(pointcutExpression, definition);
        pointCutExpressions.add(parser.parsePointcutExpression(pointcutExpression));

        if (log.isDebugEnabled()) {
            log.debug("AspectJ pointcut expression '" + pointcutExpression
                    + "' registered for security configuration attribute '" + definition
                    + "'");
        }
    }

    private String replaceBooleanOperators(String pcExpr) {
        pcExpr = StringUtils.replace(pcExpr, " and ", " && ");
        pcExpr = StringUtils.replace(pcExpr, " or ", " || ");
        pcExpr = StringUtils.replace(pcExpr, " not ", " ! ");
        return pcExpr;
    }

}
```

## SecurityResourceService 클래스 로직추가
```java
    public LinkedHashMap<String, List<ConfigAttribute>> getPointcutResourceList() {
        LinkedHashMap<String, List<ConfigAttribute>> result = new LinkedHashMap<>();

        List<Resources> resourcesList = resourcesRepository.findAllPointcutResources();
        resourcesList.forEach(x -> {
            List<ConfigAttribute> configAttributeList = new ArrayList<>();
            x.getRoleSet().forEach(role -> configAttributeList.add(new SecurityConfig(role.getRoleName())));
            result.put(x.getResourceName(), configAttributeList);
        });

        return result;
    }
```




