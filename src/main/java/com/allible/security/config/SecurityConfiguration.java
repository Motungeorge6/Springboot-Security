package com.allible.security.config;


import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import static com.allible.security.user.Permission.*;
import static com.allible.security.user.Role.ADMIN;
import static com.allible.security.user.Role.MANAGER;
import static org.springframework.http.HttpMethod.*;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity
public class SecurityConfiguration {


    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;
    private final LogoutHandler logoutHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(
                                "/api/v1/auth/**",
                                "/v2/api-docs",
                                "/v3/api-docs",
                                "/v3/api-docs/**",
                                "/swagger-resources",
                                "/swagger-resources/**",
                                "/configuration/ui",
                                "/configuration/security",
                                "/swagger-ui/**",
                                "/webjars/**",
                                "/swagger-ui.html"
                        ).permitAll()
                        .requestMatchers("/api/v1/management/**").hasAnyRole("ADMIN", "MANAGER")
                        .requestMatchers(GET, "/api/v1/management/**").hasAnyAuthority("ADMIN_READ", "MANAGER_READ")
                        .requestMatchers(POST, "/api/v1/management/**").hasAnyAuthority("ADMIN_CREATE", "MANAGER_CREATE")
                        .requestMatchers(PUT, "/api/v1/management/**").hasAnyAuthority("ADMIN_UPDATE", "MANAGER_UPDATE")
                        .requestMatchers(DELETE, "/api/v1/management/**").hasAnyAuthority("ADMIN_DELETE", "MANAGER_DELETE")
                        // Uncomment and adjust these lines if needed
                        // .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
                        // .requestMatchers(GET, "/api/v1/admin/**").hasAuthority("ADMIN_READ")
                        // .requestMatchers(POST, "/api/v1/admin/**").hasAuthority("ADMIN_CREATE")
                        // .requestMatchers(PUT, "/api/v1/admin/**").hasAuthority("ADMIN_UPDATE")
                        // .requestMatchers(DELETE, "/api/v1/admin/**").hasAuthority("ADMIN_DELETE")
                        .anyRequest().authenticated()
                )
                .sessionManagement(sessionManagement -> sessionManagement
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .logout(logout -> logout
                        .logoutUrl("/api/v1/auth/logout")
                        .addLogoutHandler(logoutHandler)
                        .logoutSuccessHandler((request, response, authentication) -> SecurityContextHolder.clearContext())
                );

        return http.build();
       /* .requestMatchers("/api/v1/admin/**").hasRole(ADMIN.name())

        .requestMatchers(GET, "/api/v1/admin/**").hasAuthority(ADMIN_READ.name())
        .requestMatchers(POST, "/api/v1/admin/**").hasAuthority(ADMIN_CREATE.name())
        .requestMatchers(PUT, "/api/v1/admin/**").hasAuthority(ADMIN_UPDATE.name())
        .requestMatchers(DELETE, "/api/v1/admin/*").hasAuthority(ADMIN_DELETE.name())/



        */
    }
}