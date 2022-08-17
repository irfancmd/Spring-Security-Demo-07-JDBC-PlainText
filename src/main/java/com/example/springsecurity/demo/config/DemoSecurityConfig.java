package com.example.springsecurity.demo.config;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.User.UserBuilder;

@Configuration
@EnableWebSecurity
public class DemoSecurityConfig extends WebSecurityConfigurerAdapter{
	
	// Add reference to the security data source
	@Autowired
	DataSource securityDataSource;
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		// Use JDBC authentication
		// If our table schema follows the spring security convension, it will automatically deal with the
		// database. We don't have to use any SQL code ourselves
		auth.jdbcAuthentication().dataSource(securityDataSource);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
			.antMatchers("/").hasRole("EMPLOYEE") // All employees will be able to access the home page
			.antMatchers("/leaders/**").hasRole("MANAGER") // Managers will be able to access leaders directory and its sub-directories
			.antMatchers("/systems/**").hasRole("ADMIN") // Admins will be able to access leaders directory and its sub-directories
			.and()
			.formLogin() // We want to use form for the login method
				.loginPage("/showMyLoginPage")
				.loginProcessingUrl("/authenticateTheUser") // Spring will process form data automatically if we use recommended form element names
				.permitAll() // Anyone will be able to see the login form
			.and()
			.logout().permitAll() // Add support for logout
			.and()
			.exceptionHandling().accessDeniedPage("/access-denied"); // Custom access denied page
	}
}
