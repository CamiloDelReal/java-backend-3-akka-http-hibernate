package org.xapps.services.repositories;

import org.xapps.services.entities.UserRole;
import org.xapps.services.repositories.utils.Repository;

public class UserRoleRepository extends Repository<UserRole, UserRole.UserRoleId> {
    public UserRoleRepository() {
        super(UserRole.class);
    }
}
