package com.example.springsecurity.demo.config;

import java.beans.PropertyVetoException;
import java.util.logging.Logger;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.env.Environment;
import org.springframework.web.servlet.ViewResolver;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.view.InternalResourceViewResolver;

import com.mchange.v2.c3p0.ComboPooledDataSource;

@Configuration
@EnableWebMvc
@ComponentScan(basePackages = "com.example.springsecurity.demo")
@PropertySource("classpath:persistence-mariadb.properties")
public class DemoAppConfig {

	// All the properties read from the property file will be stored in this environment object
	@Autowired
	private Environment env;
	
	// Setting up a logger for diagnostics
	private Logger logger = Logger.getLogger(getClass().getName());
	
	// Define bean for view resolver
	@Bean
	public ViewResolver viewResolver() {
		InternalResourceViewResolver viewResolver = new InternalResourceViewResolver();
		viewResolver.setPrefix("/WEB-INF/view/");
		viewResolver.setSuffix(".jsp");
		
		return viewResolver;
		
	}
	
	@Bean
	public DataSource securityDataSource() {
		
		// Creating connection pool
		ComboPooledDataSource dataSource = new ComboPooledDataSource();
		
		// Set the JDBC driver class
		try {
			dataSource.setDriverClass(env.getProperty("jdbc.driver"));
		} catch (PropertyVetoException e) {
			throw new RuntimeException(e);
		}
		
		// Logging connection properties
		logger.info(">>> jdbc:url=" + env.getProperty("jdbc.url"));
		logger.info(">>> jdbc:user=" + env.getProperty("jdbc.user"));
	
		// Setting the JDBC connection properties
		dataSource.setJdbcUrl(env.getProperty("jdbc.url"));
		dataSource.setUser(env.getProperty("jdbc.user"));
		dataSource.setPassword(env.getProperty("jdbc.password"));
		
		// Setting connection pool properties
		dataSource.setInitialPoolSize(getIntProperty("connection.pool.initialPoolSize"));
		dataSource.setMinPoolSize(getIntProperty("connection.pool.minPoolSize"));
		dataSource.setMaxPoolSize(getIntProperty("connection.pool.maxPoolSize"));
		dataSource.setMaxIdleTime(getIntProperty("connection.pool.maxIdleTime"));
		
		return dataSource;
	}
	
	private int getIntProperty(String propName) {
		return Integer.parseInt(env.getProperty(propName));
	}
	
}
