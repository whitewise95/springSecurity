package coid.security.springsecurity.security.service;

import coid.security.springsecurity.dmain.AccessIp;
import coid.security.springsecurity.dmain.Resources;
import coid.security.springsecurity.repository.AccessIpRepository;
import coid.security.springsecurity.repository.ResourcesRepository;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.stream.Collectors;

@Service
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

    public LinkedHashMap<String, List<ConfigAttribute>> getMethodResourceList() {
        LinkedHashMap<String, List<ConfigAttribute>> result = new LinkedHashMap<>();

        List<Resources> resourcesList = resourcesRepository.findAllMethodResources();
        resourcesList.forEach(x -> {
            List<ConfigAttribute> configAttributeList = new ArrayList<>();
            x.getRoleSet().forEach(role -> configAttributeList.add(new SecurityConfig(role.getRoleName())));
            result.put(x.getResourceName(), configAttributeList);
        });

        return result;
    }

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

    public List<String> getAccessIpList() {
        return accessIpRepository.findAll().stream().map(AccessIp::getIpAddress).collect(Collectors.toList());
    }


}
