package com.example.springsecurity.demo.config;

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
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		// Add users for in memory authentication
		UserBuilder users = User.withDefaultPasswordEncoder();

		auth.inMemoryAuthentication()
		.withUser(users.username("akkas").password("123").roles("EMPLOYEE"))
		.withUser(users.username("abdul").password("123").roles("EMPLOYEE", "MANAGER"))
		.withUser(users.username("Motin").password("123").roles("EMPLOYEE", "ADMIN"));

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
