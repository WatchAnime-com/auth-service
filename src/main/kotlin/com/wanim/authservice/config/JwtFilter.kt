package com.wanim.authservice.config

import com.wanim.authservice.repo.AuthRepo
import com.wanim.authservice.service.JwtService
import com.wanim.authservice.service.auth.IAuthService
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter

@Component
class JwtFilter(
    private val authService: IAuthService,
    private val jwtService: JwtService,
    private val repo: AuthRepo,
    private val userDetailsService: UserDetailsService
) : OncePerRequestFilter() {

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        // Skip the authentication filter for authentication-related endpoints
        if (request.servletPath.contains("/api/v1/auth")) {
            filterChain.doFilter(request, response)
            return
        }

        // Retrieve the Authorization header
        val authHeader: String? = request.getHeader("Authorization")

        // If no Authorization header or if it's not a Bearer token, just continue the filter chain
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response)
            return
        }

        // Extract the JWT token
        val jwtToken: String = authHeader.substring(7) // Remove "Bearer " from the token

        // If there's no JWT token, continue the filter chain
        if (jwtToken.isEmpty()) {
            filterChain.doFilter(request, response)
            return
        }

        // Validate the token using the auth service
        if (!authService.authUser(jwtToken)) {
            filterChain.doFilter(request, response)
            return
        }

        // Extract the user's email from the token
        val email = jwtService.extractSubject(jwtToken)

        // Load the user details using UserDetailsService
        val userDetails: UserDetails = userDetailsService.loadUserByUsername(email)

        // Create a new authentication token using the user details
        val authToken = UsernamePasswordAuthenticationToken(
            userDetails,
            null,
            userDetails.authorities
        )

        // Set the details of the authentication token
        authToken.details = WebAuthenticationDetailsSource().buildDetails(request)

        // Set the authentication in the SecurityContext
        SecurityContextHolder.getContext().authentication = authToken

        // Continue the filter chain
        filterChain.doFilter(request, response)
    }
}
