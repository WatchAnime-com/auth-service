package com.wanim.authservice.service.auth

import com.wanim.authservice.dto.CUser
import com.wanim.authservice.dto.LUser
import com.wanim.authservice.dto.RUser
import com.wanim.authservice.enums.AuthRole
import com.wanim.authservice.enums.Perms
import com.wanim.authservice.error.Exceptions
import com.wanim.authservice.mapper.AuthMapper
import com.wanim.authservice.model.UserModel
import com.wanim.authservice.params.AuthParams
import com.wanim.authservice.repo.AuthRepo
import com.wanim.authservice.service.JwtService
import com.wanim.authservice.spec.AuthSpec
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.data.domain.PageRequest
import org.springframework.data.domain.Pageable
import org.springframework.stereotype.Service
import java.security.SecureRandom

@Service
class IAuthService(
    private val repo: AuthRepo,
    private val mapper: AuthMapper,
    private val jwtService: JwtService,
    private val request: HttpServletRequest,
    private val response: HttpServletResponse,
) : AuthService {

    override fun registerUser(cUser: CUser): RUser {

        cUser.email = cUser.email.lowercase()

        val emailRegex = "^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$"
        if (!cUser.email.matches(emailRegex.toRegex())) {
            throw Exceptions.BadRequestEx("Invalid email format")
        }
        if (cUser.password.length < 5) {
            throw Exceptions.BadRequestEx("Password must be at least 5 characters long")
        }

        val dbUser = repo.findOne(AuthSpec(AuthParams()).apply {
            archived = false
            deleted = false
            email = cUser.email
        }.ofSearch())
        if (!dbUser.isEmpty) {
            throw Exceptions.BadRequestEx("Email in use")
        }
        val newUserModel = UserModel()
        newUserModel.setPassword(cUser.password)
        newUserModel.userName = cUser.username
        newUserModel.email = cUser.email
        newUserModel.preUpdate()

        val generatedToken = jwtService.generateToken(newUserModel)
        return mapper.createResponse(save(newUserModel)).apply {
            token = generatedToken
        }
    }

    override fun login(lUser: LUser): RUser {
        lUser.email = lUser.email.lowercase()
        val dbUser = repo.findOne(AuthSpec(AuthParams()).apply {
            archived = false
            deleted = false
            email = lUser.email
        }.ofSearch()).orElseThrow { throw Exceptions.BadRequestEx("Invalid email") }
        if (!dbUser.isPasswordMatch(lUser.password)) {
            throw Exceptions.BadRequestEx("Password does not match")
        }
        return mapper.createResponse(dbUser).apply {
            token = jwtService.generateToken(dbUser)
        }
    }

    override fun logoutAll() {
        val dbUser = repo.findOne(AuthSpec(AuthParams()).apply {
            archived = false
            deleted = false
            email = getEmail()
        }.ofSearch()).orElseThrow { throw Exceptions.BadRequestEx("Invalid email") }
        dbUser.pk = generatePk()
        save(dbUser)
    }

    override fun authUser(token: String): Boolean {
        val tokenExtractedModel = jwtService.extractClaims(token)
        val tokenPk = jwtService.extractClaims(token) { claims -> claims["pk"] as Long? }

        if (repo.findOne(AuthSpec(AuthParams()).apply {
                archived = false
                deleted = false
                pk = tokenPk
                email = tokenExtractedModel.subject
            }.ofSearch()).isEmpty) {
            return false
        }

        if (jwtService.isTokenExpired(token)) {
            throw Exceptions.BadRequestEx("Token is expired")
        }
        return true
    }

    override fun findOne(authParams: AuthParams): RUser {
        val user = repo.findOne(AuthSpec(authParams).apply {
            deleted = false
            archived = false
        }.ofSearch()).orElseThrow {
            Exceptions.BadRequestEx("User is not found")
        }
        return mapper.createResponse(user).apply {
            val rolesList = mutableListOf<String>()
            user.getAuth().forEach { role ->
                rolesList.add(role.toString())
            }
            roles = rolesList
            token = "not defined"
        }
    }

    override fun findAll(authParams: AuthParams, page: Int, itemsPerPage: Int): MutableList<RUser> {
        val pageable: Pageable = PageRequest.of(page, itemsPerPage)
        val userPage = repo.findAll(AuthSpec(authParams).apply {
            deleted = false
            archived = false
        }.ofSearch(), pageable)
        return userPage.content.map { user ->
            mapper.createResponse(user).apply {
                val rolesList = mutableListOf<String>()
                user.getAuth().forEach { role ->
                    rolesList.add(role.toString())
                }
                roles = rolesList
                token = "not defined"
            }
        }.toMutableList()
    }

    override fun addPermission(permission: Perms, email: String): UserModel {
        val user = repo.findOne(AuthSpec(AuthParams()).apply {
            deleted = false
            archived = false
            this.email = email.lowercase()
        }.ofSearch()).orElseThrow {
            throw Exceptions.BadRequestEx("User is not found")
        }
        if (user.permissions.contains(permission)) {
            throw Exceptions.BadRequestEx("Perms already exists")
        }
        user.permissions.add(permission)
        return save(user)
    }

    override fun removePermission(permission: Perms, email: String): UserModel {
        val user = repo.findOne(AuthSpec(AuthParams()).apply {
            deleted = false
            archived = false
            this.email = email.lowercase()
        }.ofSearch()).orElseThrow {
            throw Exceptions.BadRequestEx("User is not found")
        }
        if (!user.permissions.contains(permission)) {
            throw Exceptions.BadRequestEx("Perms does not exist")
        }
        user.permissions.remove(permission)
        return save(user)
    }


    override fun deleteUser(email: String): Boolean {
        val user = repo.findOne(AuthSpec(AuthParams()).apply {
            deleted = false
            archived = false
            this.email = email.lowercase()
        }.ofSearch()).orElseThrow {
            Exceptions.BadRequestEx("User is not found")
        }
        user.deleted = true
        save(user)
        return true
    }
    override fun getPermissionList(): MutableList<Perms> {
        return Perms.values().toMutableList()
    }

    override fun getRoles(): MutableList<AuthRole> {
        return AuthRole.values().toMutableList()
    }


    fun getEmail(): String? {
        val authHeader: String? = request.getHeader("Authorization")
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return null
        }
        val jwtToken: String = authHeader.substring(7)
        if (jwtToken.length < 5) {
            return null
        }
        if (!authUser(jwtToken)) {
            return null
        }
        val email = jwtService.extractSubject(jwtToken)
        return email
    }


    fun save(user: UserModel): UserModel {
        return repo.save(user)
    }

    fun generatePk(): Long {
        val secureRandom = SecureRandom()
        val randomBits = secureRandom.nextLong()
        val nanoTime = System.nanoTime()
        return (randomBits xor nanoTime) and Long.MAX_VALUE
    }

}