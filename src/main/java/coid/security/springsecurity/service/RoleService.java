package coid.security.springsecurity.service;

import coid.security.springsecurity.dmain.Role;
import coid.security.springsecurity.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Slf4j
@RequiredArgsConstructor
@Service
public class RoleService {

    private final RoleRepository roleRepository;

    @Transactional
    public Role getRole(long id) {
        return roleRepository.findById(id).orElse(new Role());
    }

    @Transactional
    public List<Role> getRoles() {

        return roleRepository.findAll();
    }

    @Transactional
    public void createRole(Role role) {

        roleRepository.save(role);
    }

    @Transactional
    public void deleteRole(long id) {
        roleRepository.deleteById(id);
    }
}