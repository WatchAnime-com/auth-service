package com.wanim.authservice.custom

import com.wanim.authservice.model.UserModel
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.UserDetails

class UserPrincipal(private val user: UserModel) : UserDetails {

    override fun getAuthorities(): Collection<GrantedAuthority> {
        return user.getAuthorities()  // Make sure this is implemented in your UserModel
    }

    override fun getPassword(): String {
        return user.password
    }

    override fun getUsername(): String {
        return user.email ?: ""  // Ensure email is being correctly returned
    }

    override fun isAccountNonExpired(): Boolean {
        return !user.deleted
    }

    override fun isAccountNonLocked(): Boolean {
        return !user.archived
    }

    override fun isCredentialsNonExpired(): Boolean {
        return true
    }

    override fun isEnabled(): Boolean {
        return true
    }
}
