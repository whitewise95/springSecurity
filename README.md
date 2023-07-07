# 3-7 로그아웃 및 인증에 따른 화면 보안 처리


## gradle 추가
```gradle
implementation 'org.thymeleaf.extras:thymeleaf-extras-springsecurity5:3.0.4.RELEASE'
```


## top.html 에 코드추가
- 로그아웃 버튼생성
- gradle 추가하고 네임스페이스를 추가한다.
- 네임스페이드 기능으로 isAnonymous와 isAuthenticated 로 현재 인증상태에 따라 버튼을 히든처리할 수 있다.
```html
<!DOCTYPE html>
<html lang="ko" xmlns:th="http://www.thymeleaf.org"
      xmlns:sec="http://www.thymeleaf.org/thymeleaf-extras-springsecurity5"> <!-- 네임스페이스 --> 
<div th:fragment="header">
    <nav class="navbar navbar-dark sticky-top bg-dark ">
        <div class="container">
            <a class="text-light" href="#"><h4>Core Spring Security</h4></a>
            <ul class="nav justify-content-end">
                <li class="nav-item" sec:authorize="isAnonymous()"  <!-- 네임스페이드 기능 -->  ><a class="nav-link text-light" th:href="@{/login}">로그인</a></li>
                <li class="nav-item" sec:authorize="isAnonymous()"><a class="nav-link text-light" th:href="@{/users}">회원가입</a></li>
                <li class="nav-item" sec:authorize="isAuthenticated()"><a class="nav-link text-light" th:href="@{/logout}">로그아웃</a></li>
                <li class="nav-item" ><a class="nav-link text-light" href="/">HOME</a></li>
            </ul>
        </div>
    </nav>
</div>
</html>
```


## 컨트롤러에서 로그아웃 핸들링
```java
    @GetMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null){
            new SecurityContextLogoutHandler().logout(request, response, authentication);
        }

        return "redirect:/login";
    }
```