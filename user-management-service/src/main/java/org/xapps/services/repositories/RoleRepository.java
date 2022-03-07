package org.xapps.services.repositories;

import lombok.extern.slf4j.Slf4j;
import org.hibernate.Session;
import org.xapps.services.entities.Role;
import org.xapps.services.repositories.utils.Repository;

import javax.persistence.NoResultException;
import javax.persistence.TypedQuery;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
public class RoleRepository extends Repository<Role, Long> {
    public RoleRepository() {
        super(Role.class);
    }

    public List<Role> getByIds(List<Long> ids) {
        Session session = sessionFactory.openSession();
        session.beginTransaction();
        TypedQuery<Role> query = session.createQuery("SELECT r FROM roles r WHERE r.id IN :ids", Role.class);
        query.setParameter("ids", ids);
        List<Role> roles = null;
        try {
            roles = query.getResultList();
        } catch (NoResultException ex) {
            log.debug("No roles found for ids " + ids.stream().map(Object::toString).collect(Collectors.joining(", ")));
        } catch (Exception ex) {
            log.error("Exception captured", ex);
        }
        session.getTransaction().commit();
        session.close();
        return roles;
    }

    public List<Role> getByNames(List<String> names) {
        Session session = sessionFactory.openSession();
        session.beginTransaction();
        TypedQuery<Role> query = session.createQuery("SELECT r FROM roles r WHERE r.name IN :names", Role.class);
        query.setParameter("names", names);
        List<Role> roles = null;
        try {
            roles = query.getResultList();
        } catch (NoResultException ex) {
            log.debug("No roles found for names " + String.join(", ", names));
        } catch (Exception ex) {
            log.error("Exception captured", ex);
        }
        session.getTransaction().commit();
        session.close();
        return roles;
    }

    public Role getByName(String name) {
        Session session = sessionFactory.openSession();
        session.beginTransaction();
        TypedQuery<Role> query = session.createQuery("SELECT r FROM roles r WHERE r.name = :name", Role.class);
        query.setParameter("name", name);
        Role role = null;
        try {
            role = query.getSingleResult();
        } catch (NoResultException ex) {
            log.debug("No role found with name " + name);
        } catch (Exception ex) {
            log.error("Exception captured", ex);
        }
        session.getTransaction().commit();
        session.close();
        return role;
    }
}
