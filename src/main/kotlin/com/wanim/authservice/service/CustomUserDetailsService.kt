package com.wanim.authservice.service

@Service
class CustomUserDetailsService(
    private val repo: UserRepo
) : UserDetailsService {

    override fun loadUserByUsername(username: String): UserDetails {
        // Try to fetch user by email, and make sure it's not deleted or archived
        val user = repo.findByEmailAndNotDeletedAndNotArchived(username, false, false)
            .orElseThrow { UsernameNotFoundException("$username not found") }

        // Returning a UserPrincipal that implements UserDetails
        return UserPrincipal(user)
    }
}
