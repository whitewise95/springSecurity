package coid.security.springsecurity.service;

import coid.security.springsecurity.dmain.RoleHierarchy;
import coid.security.springsecurity.repository.RoleHierarchyRepository;
import java.util.Iterator;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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
