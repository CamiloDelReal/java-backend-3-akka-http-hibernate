package org.xapps.services.repositories;

import lombok.extern.slf4j.Slf4j;
import org.hibernate.Session;
import org.xapps.services.entities.User;
import org.xapps.services.repositories.utils.Repository;

import javax.persistence.NoResultException;
import javax.persistence.TypedQuery;

@Slf4j
public class UserRepository extends Repository<User, Long> {
    public UserRepository() {
        super(User.class);
    }

    public User getByEmail(String email) {
        Session session = sessionFactory.openSession();
        session.beginTransaction();
        TypedQuery<User> query = session.createQuery("SELECT u FROM users u WHERE u.email = :email", User.class);
        query.setParameter("email", email);
        User user = null;
        try {
            user = query.getSingleResult();
        } catch (NoResultException ex) {
            log.debug("No user found for email " + email);
        }
        session.getTransaction().commit();
        session.close();
        return user;
    }

    public User getByNotIdAndEmail(Long id, String email) {
        Session session = sessionFactory.openSession();
        session.beginTransaction();
        TypedQuery<User> query = session.createQuery("SELECT u FROM users u WHERE u.id != :id AND u.email = :email", User.class);
        query.setParameter("id", id);
        query.setParameter("email", email);
        User user = null;
        try {
            user = query.getSingleResult();
        } catch (NoResultException ex) {
            log.debug("No user found for id not equal to " + id + " and email equal to " + email);
        } catch (Exception ex) {
            log.error("Exception captured", ex);
        }
        session.getTransaction().commit();
        session.close();
        return user;
    }
}
