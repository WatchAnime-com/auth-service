package com.wanim.authservice.config

import com.wanim.authservice.enums.AuthRole
import com.wanim.authservice.enums.Perms
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Role
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter

@Configuration
@EnableWebSecurity
class SecurityConfig(
    private val jwtFilter: JwtFilter
) {

    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .csrf { csr -> csr.disable() }
            .authorizeHttpRequests { authz ->
                authz
                    .requestMatchers("/api/v1/auth/login","/api/v1/auth/register").permitAll()
                    .requestMatchers("api/v1/videolist/update/anime-list").hasAnyAuthority(AuthRole.ADMIN.name)
                    .anyRequest().authenticated()
            }
            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter::class.java)
        return http.build()
    }
}