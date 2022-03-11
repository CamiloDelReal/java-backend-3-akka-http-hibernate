package org.xapps.services.repositories.utils;

import lombok.extern.slf4j.Slf4j;
import org.hibernate.Session;
import org.hibernate.SessionFactory;

import javax.naming.NameNotFoundException;
import javax.persistence.*;
import java.lang.reflect.Field;
import java.util.List;

@Slf4j
public class Repository<T, I> {
    protected final SessionFactory sessionFactory;
    private final Class<T> typeParameterClass;
    private final String tableName;
    private final String idFieldName;

    public Repository(Class<T> typeParameterClass) {
        sessionFactory = SessionFactoryProvider.getInstance().buildSessionFactory();
        this.typeParameterClass = typeParameterClass;
        String tableNameByAnnotation = typeParameterClass.getAnnotation(Entity.class).name();
        if (tableNameByAnnotation != null && !tableNameByAnnotation.isEmpty() && !tableNameByAnnotation.isBlank()) {
            this.tableName = tableNameByAnnotation;
        } else {
            this.tableName = typeParameterClass.getName();
        }
        String idFieldNameByAnnotation = null;
        Field[] entityFields = this.typeParameterClass.getDeclaredFields();
        int i = 0;
        while (i < entityFields.length && idFieldNameByAnnotation == null) {
            Id idAnnotation = entityFields[i].getAnnotation(Id.class);
            if (idAnnotation != null) {
                Column columnAnnotation = entityFields[i].getAnnotation(Column.class);
                if (columnAnnotation != null) {
                    idFieldNameByAnnotation = columnAnnotation.name();
                    if (idFieldNameByAnnotation == null || idFieldNameByAnnotation.isEmpty() || idFieldNameByAnnotation.isBlank()) {
                        idFieldNameByAnnotation = entityFields[i].getName();
                    }
                } else {
                    idFieldNameByAnnotation = entityFields[i].getName();
                }
            }
            i++;
        }
        this.idFieldName = idFieldNameByAnnotation;
    }

    public Long count() {
        Session session = sessionFactory.openSession();
        session.beginTransaction();
        Long count = session.createQuery(String.format("SELECT COUNT(*) FROM %s r", tableName), Long.class).getSingleResult();
        session.getTransaction().commit();
        session.close();
        return count;
    }

    public T create(T obj) {
        Session session = sessionFactory.openSession();
        session.beginTransaction();
        session.save(obj);
        session.getTransaction().commit();
        session.close();
        return obj;
    }

    public List<T> readAll() {
        Session session = sessionFactory.openSession();
        session.beginTransaction();
        List<T> objs = session.createQuery(String.format("SELECT r FROM %s r", tableName), typeParameterClass).getResultList();
        session.getTransaction().commit();
        session.close();
        return objs;
    }

    public T read(I id) {
        if (idFieldName == null) {
            log.warn("Field marked as Id not found");
            return null;
        }
        Session session = sessionFactory.openSession();
        session.beginTransaction();
        TypedQuery<T> query = session.createQuery(String.format("SELECT r FROM %s r WHERE r.%s = :id", tableName, idFieldName), typeParameterClass);
        query.setParameter("id", id);
        T obj = null;
        try {
            obj = query.getSingleResult();
        } catch (NoResultException ex) {
            log.debug("No entity found for id " + id);
        }
        session.getTransaction().commit();
        session.close();
        return obj;
    }

    public T update(T obj) {
        Session session = sessionFactory.openSession();
        session.beginTransaction();
        session.update(obj);
        session.getTransaction().commit();
        session.close();
        return obj;
    }

    public T delete(T obj) {
        Session session = sessionFactory.openSession();
        session.beginTransaction();
        session.delete(obj);
        session.getTransaction().commit();
        session.close();
        return obj;
    }
}
