package org.xapps.services.repositories.utils;

import org.hibernate.SessionFactory;
import org.hibernate.boot.MetadataSources;
import org.hibernate.boot.registry.StandardServiceRegistry;
import org.hibernate.boot.registry.StandardServiceRegistryBuilder;

public class SessionFactoryProvider {
    private final StandardServiceRegistry registry;
    private static SessionFactoryProvider instance;

    public static SessionFactoryProvider getInstance() {
        if (instance == null) {
            instance = new SessionFactoryProvider();
        }
        return instance;
    }

    private SessionFactoryProvider() {
        registry = new StandardServiceRegistryBuilder()
                .configure()
                .build();
    }

    public SessionFactory buildSessionFactory() {
        return new MetadataSources(registry).buildMetadata().buildSessionFactory();
    }
}
