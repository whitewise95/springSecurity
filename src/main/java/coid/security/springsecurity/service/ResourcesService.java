package coid.security.springsecurity.service;

import coid.security.springsecurity.dmain.Resources;
import coid.security.springsecurity.repository.ResourcesRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Slf4j
@RequiredArgsConstructor
@Service
public class ResourcesService {

    private final ResourcesRepository resourcesRepository;

    @Transactional
    public Resources getResources(long id) {
        return resourcesRepository.findById(id).orElse(new Resources());
    }

    @Transactional
    public List<Resources> getResources() {
        return resourcesRepository.findAll(Sort.by(Sort.Order.asc("orderNum")));
    }

    @Transactional
    public void createResources(Resources resources) {
        resourcesRepository.save(resources);
    }

    @Transactional
    public void deleteResources(long id) {
        resourcesRepository.deleteById(id);
    }
}