package com.wanim.authservice.service

import com.wanim.authservice.custom.UserPrincipal
import com.wanim.authservice.params.AuthParams
import com.wanim.authservice.repo.AuthRepo
import com.wanim.authservice.spec.AuthSpec
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.stereotype.Service

@Service
class CustomUserDetailsService(
    private val repo: AuthRepo
) : UserDetailsService {

    override fun loadUserByUsername(username: String): UserDetails {
        val user = repo.findOne(AuthSpec(AuthParams()).apply {
            deleted = false
            archived = false
            email = username
        }.ofSearch()).orElseThrow { throw RuntimeException("User $username not found") }
        return UserPrincipal(user)
    }
}
