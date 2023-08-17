package io.gigyesik.resourceserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class SecurityConfig {
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .authorizeHttpRequests(request -> request
                    .requestMatchers("/messages/**").hasAuthority("SCOPE_message.read"))
                .oauth2ResourceServer(resource -> resource.jwt(Customizer.withDefaults()));
        return httpSecurity.build();
    }
}
