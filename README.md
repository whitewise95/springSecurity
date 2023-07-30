# 5-7) Ajax 로그인 구현 & CSRF 설정

## login.html
- ajax로 통신하기 때문에 ajax 로직을 추가한다.
- csrf 사용하기 때문에 csrf를 받는 meta 태크를 추가한다.
```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">

<meta id="_csrf" name="_csrf" th:content="${_csrf.token}"/>
<meta id="_csrf_header" name="_csrf_header" th:content="${_csrf.headerName}"/>

<head th:replace="layout/header::userHead"></head>
<script>
    function formLogin(e) {

        var username = $("input[name='username']").val().trim();
        var password = $("input[name='password']").val().trim();
        var data = {"username" : username, "password" : password};

        var csrfHeader = $('meta[name="_csrf_header"]').attr('content')
        var csrfToken = $('meta[name="_csrf"]').attr('content')

        $.ajax({
            type: "post",
            url: "/api/login",
            data: JSON.stringify(data),
            dataType: "json",
            beforeSend : function(xhr){
                xhr.setRequestHeader(csrfHeader, csrfToken);
                xhr.setRequestHeader("X-Requested-With", "XMLHttpRequest");
                xhr.setRequestHeader("Content-type","application/json");
            },
            success: function (data) {
                console.log(data);
                window.location = '/';
            },
            error : function(xhr, status, error) {
                console.log(error);
                window.location = '/api/login?error=true&exception=' + xhr.responseText;
            }
        });
    }
</script>
<body>
<div th:replace="layout/top::header"></div>
<div class="container text-center">
    <div class="login-form d-flex justify-content-center">
        <div class="col-sm-5" style="margin-top: 30px;">
            <div class="panel">
                <p>아이디와 비밀번호를 입력해주세요</p>
            </div>
            <div th:if="${param.error}" class="form-group">
                <span th:text="${exception}" class="alert alert-danger">잘못된 아이디나 암호입니다</span>
            </div>
            <form th:action="@{/login_proc}" class="form-signin" method="post">
                <input type="hidden" th:value="secret" name="secret_key" />
                <div class="form-group">
                    <input type="text" class="form-control" name="username" placeholder="아이디" required="required" autofocus="autofocus">
                </div>
                <div class="form-group">
                    <input type="password" class="form-control" name="password" placeholder="비밀번호" required="required">
                </div>
                <button type="button" onclick="formLogin()" id="formbtn" class="btn btn-lg btn-primary btn-block">로그인</button>
                <!--<button type="submit" class="btn btn-lg btn-primary btn-block">로그인</button>-->
            </form>
        </div>
    </div>
</div>
</body>
</html>
```


## home.html
- login.html와 같이 ajax와 csrf를 이용한 로직을 추가한다.
```html
<!DOCTYPE html>
<html lang="ko" xmlns:th="http://www.thymeleaf.org">
<head th:replace="layout/header::userHead"></head>
<html xmlns:th="http://www.thymeleaf.org">

<meta name="_csrf" th:content="${_csrf?.token}" th:if="${_csrf} ne null">
<meta name="_csrf_header" th:content="${_csrf?.headerName}" th:if="${_csrf} ne null">

<script>
    function messages() {

        var csrfHeader = $('meta[name="_csrf_header"]').attr('content')
        var csrfToken = $('meta[name="_csrf"]').attr('content')

        $.ajax({
            type: "post",
            url: "/api/messages",
            //dataType: "json",
            beforeSend : function(xhr){
                xhr.setRequestHeader(csrfHeader, csrfToken);
                xhr.setRequestHeader("X-Requested-With", "XMLHttpRequest");
                xhr.setRequestHeader("Content-type","application/json");
            },
            success: function (data) {
                console.log(data);
                window.location = '/messages';
            },
            error : function(xhr, status, error) {
                console.log(error);
                if(xhr.status == 401){
                    window.location = '/api/login';
                }else if(xhr.status == 403){
                    window.location = '/api/denied';
                }
            }
        });
    }
</script>
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
                            <a href="#" onclick="messages()" style="margin:5px;" class="nav-link text-primary">메시지</a>
                            <a th:href="@{/config}" style="margin:5px;" class="nav-link text-primary">환경설정</a>
                        </div>
                    </li>
                </ul>
            </div>
        </nav>
        <div style="padding-top:50px;"  class="col">
            <div class="container text-center">
                <h1 class="text-primary">DASHBOARD</h1>
                <div class="security"></div>
                <h1>Core Spring Security 에 오신 것을 환영합니다.</h1>
            </div>
        </div>
    </div>
</div>
<div th:replace="layout/footer::footer"></div>
</body>
</html>
```

## top.html
- 로그인의 href 를 /login -> /api/login으로 변경한다.
```html
<!DOCTYPE html>
<html lang="ko" xmlns:th="http://www.thymeleaf.org"
      xmlns:sec="http://www.thymeleaf.org/thymeleaf-extras-springsecurity5">
<div th:fragment="header">
    <nav class="navbar navbar-dark sticky-top bg-dark ">
        <div class="container">
            <a class="text-light" href="#"><h4>Core Spring Security</h4></a>
            <ul class="nav justify-content-end">
                <li class="nav-item" sec:authorize="isAnonymous()" ><a class="nav-link text-light" th:href="@{/api/login}">로그인</a></li>
                <li class="nav-item" sec:authorize="isAnonymous()"><a class="nav-link text-light" th:href="@{/users}">회원가입</a></li>
                <li class="nav-item" sec:authorize="isAuthenticated()"><a class="nav-link text-light" th:href="@{/logout}">로그아웃</a></li>
                <li class="nav-item" ><a class="nav-link text-light" href="/">HOME</a></li>
            </ul>
        </div>
    </nav>
</div>
</html>
```
## SecurityConfig
- csrf를 사용하기 때문에 해당 로직을 주석처리해준다.
```java
		// http.csrf().disable(); 
```

## AjaxSecurityConfig
- `	.antMatchers("/api/login").permitAll()` 해당로직을 설정해준다.
```java
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@Order(0)
public class AjaxSecurityConfig extends WebSecurityConfigurerAdapter {

	private final AjaxAuthenticationProvider authenticationProvider;

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(authenticationProvider);
	}

	@Bean
	public AuthenticationSuccessHandler ajaxAuthenticationSuccessHandler() {
		return new AjaxAuthenticationSuccessHandler();
	}

	@Bean
	public AuthenticationFailureHandler ajaxAuthenticationFailureHandler() {
		return new AjaxAuthenticationFailureHandler();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.antMatcher("/api/**") // 이 엔드포인트로만 동작하도록 설정
			.authorizeRequests()
			.antMatchers("/api/messages").hasRole("MANAGER")
			.antMatchers("/api/login").permitAll()
			.anyRequest().authenticated()
			.and()
			.addFilterBefore(ajaxLoginProcessingFilter(), UsernamePasswordAuthenticationFilter.class);

		http
			.exceptionHandling()
			.authenticationEntryPoint(new AjaxLoginAuthenticationEntryPoint())
			.accessDeniedHandler(ajaxAccessDeniedHandler());
	}

	@Bean
	public AccessDeniedHandler ajaxAccessDeniedHandler() {
		return new AjaxAccessDeniedHandler();
	}

	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Bean
	public AjaxLoginProcessingFilter ajaxLoginProcessingFilter() throws Exception {
		AjaxLoginProcessingFilter ajaxLoginProcessingFilter = new AjaxLoginProcessingFilter();
		ajaxLoginProcessingFilter.setAuthenticationManager(authenticationManagerBean());
		ajaxLoginProcessingFilter.setAuthenticationSuccessHandler(ajaxAuthenticationSuccessHandler());
		ajaxLoginProcessingFilter.setAuthenticationFailureHandler(ajaxAuthenticationFailureHandler());
		return ajaxLoginProcessingFilter;
	}
}

```

## MessageController
```java
@Controller
public class MessageController {
	
	@GetMapping(value="/messages")
	public String mypage() throws Exception {
		return "user/messages";
	}

	@ResponseBody
	@PostMapping("/api/messages")
	public ResponseEntity apiMessge(){
		return ResponseEntity.ok().body("ok");
	}
}

```

## LoginController
- login(), accessDenied()의 엔드포인트를 추가해준다.
```java
@Controller
public class LoginController {

    @GetMapping(value = {"/login", "/api/login"})
    public String login(@RequestParam(value = "error", required = false) Boolean error,
                        @RequestParam(value = "exception", required = false) String exception,
                        Model model) {
        model.addAttribute("error", error);
        model.addAttribute("exception", exception);
        return "user/login/login";
    }


    @GetMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null) {
            new SecurityContextLogoutHandler().logout(request, response, authentication);
        }

        return "redirect:/login";
    }

    @GetMapping(value = {"/denied", "/api/denied"})
    public String accessDenied(@RequestParam(value = "exception", required = false) String exception,
                               Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Account account = (Account) authentication.getPrincipal();
        model.addAttribute("username", account.getUsername());
        model.addAttribute("exception", exception);
        return "user/login/denied";
    }
}

```


