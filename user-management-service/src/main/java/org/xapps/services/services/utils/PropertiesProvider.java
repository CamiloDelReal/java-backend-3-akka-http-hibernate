package org.xapps.services.services.utils;

import lombok.extern.slf4j.Slf4j;

import java.io.InputStream;
import java.util.Properties;

@Slf4j
public class PropertiesProvider {
    private static PropertiesProvider instance = null;

    public static PropertiesProvider getInstance() {
        if (instance == null) {
            instance = new PropertiesProvider();
        }
        return instance;
    }

    private Properties properties;

    public PropertiesProvider() {
        try {
            InputStream inputStream = ClassLoader.getSystemResourceAsStream("application.properties");
            properties = new Properties();
            properties.load(inputStream);
        } catch (Exception ex) {
            log.error("Exception captured", ex);
            throw new RuntimeException("Application properties file could not be loaded");
        }
    }

    public String securityTokenKey() {
        return (String) properties.get("security.token-key");
    }

    public Long securityValidity() {
        return Long.parseLong((String) properties.get("security.validity"));
    }
}
