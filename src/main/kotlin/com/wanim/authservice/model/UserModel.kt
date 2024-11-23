package com.wanim.authservice.model

import com.wanim.authservice.enums.AuthRole
import com.wanim.authservice.enums.Perms
import jakarta.persistence.*
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import java.security.SecureRandom
import java.time.LocalDateTime
import java.util.*

@Entity
@Table(name = "user_accounts")
class UserModel : UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    val id: UUID? = null

    val publicId: Long = generatePk()

    private var password: String = ""

    // Remove @Enumerated annotation for email
    var email: String? = null

    var userName: String = ""

    @Column(nullable = false, unique = true)
    var pk: Long = generatePk()

    @Enumerated(EnumType.STRING)
    var role: AuthRole = AuthRole.USER

    @Lob
    @Column(nullable = false, updatable = false, unique = true)
    var sk: ByteArray = generateRandomKey()

    override fun getAuthorities(): MutableCollection<out GrantedAuthority> {
        return getAuth().toMutableList()
    }

    fun getAuth(): List<SimpleGrantedAuthority> {
        val grantedRoles: MutableList<SimpleGrantedAuthority> = mutableListOf()
        role.getAuth().forEach { grantedRoles.add(it) }
        permissions.forEach { perms ->
            val permissionAuthority = SimpleGrantedAuthority("ROLE_${perms.name}")
            if (grantedRoles.none { it.authority == permissionAuthority.authority }) {
                grantedRoles.add(permissionAuthority)
            }
        }

        return grantedRoles
    }



    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(
        name = "user_roles",
        joinColumns = [JoinColumn(name = "user_id")]
    )
    @Column(name = "permissions", nullable = false)
    var permissions: MutableList<Perms> = mutableListOf()

    fun setPassword(rawPassword: String) {
        this.password = bcryptEncoder.encode(rawPassword)
    }

    fun isPasswordMatch(rawPassword: String): Boolean {
        return bcryptEncoder.matches(rawPassword, this.password)
    }

    @Column(nullable = false)
    var deleted: Boolean = false

    @Column(nullable = false)
    var archived: Boolean = false


    fun preUpdate() {
        updatedAt = LocalDateTime.now()
    }

    @Column(nullable = false)
    var createdAt: LocalDateTime = LocalDateTime.now()

    @Column(nullable = false)
    var updatedAt: LocalDateTime? = null

    override fun getPassword(): String {
        return ""
    }

    override fun getUsername(): String {
        return this.email.toString()
    }

    fun setUsername(usr: String) {
        userName = usr
    }


    override fun isAccountNonExpired(): Boolean {
        return true
    }

    override fun isAccountNonLocked(): Boolean {
        return true
    }

    override fun isCredentialsNonExpired(): Boolean {
        return true
    }

    override fun isEnabled(): Boolean {
        return true
    }

    companion object {
        private val bcryptEncoder = BCryptPasswordEncoder()

        fun generateRandomKey(): ByteArray {
            val random = UUID.randomUUID().toString()
            return random.toByteArray()
        }

        fun generatePk(): Long {
            val secureRandom = SecureRandom()
            val randomBits = secureRandom.nextLong()
            val nanoTime = System.nanoTime()
            return (randomBits xor nanoTime) and Long.MAX_VALUE // Negatif olmaması için
        }
    }
}