package com.wanim.authservice.controller.com.wanim.authservice

import com.wanim.authservice.dto.CUser
import com.wanim.authservice.dto.LUser
import com.wanim.authservice.dto.RUser
import com.wanim.authservice.enums.AuthRole
import com.wanim.authservice.enums.Perms
import com.wanim.authservice.model.UserModel
import com.wanim.authservice.params.AuthParams
import com.wanim.authservice.service.auth.IAuthService
import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("/api/v1")
class AuthController(
    private val authService: IAuthService // Make sure the interface is used here
) {

    // Endpoint for registering a user
    @PostMapping(path = ["/auth/register"])
    fun register(@RequestBody cUser: CUser): RUser {
        return authService.registerUser(cUser)
    }

    // Endpoint for logging in a user
    @PostMapping(path = ["/auth/login"])
    fun login(@RequestBody lUser: LUser): RUser {
        return authService.login(lUser)
    }

    // Endpoint for logging out all users
    @PostMapping(path = ["/auth/logoutAll"])
    fun logoutAll() {
        authService.logoutAll()
    }

    // Endpoint for authenticating a user using a token
    @PostMapping(path = ["/auth/manage/users/authUser"])
    fun authUser(@RequestHeader("Authorization") token: String): Boolean {
        return authService.authUser(token.removePrefix("Bearer "))
    }

    // Endpoint to get a single user by parameters
    @PostMapping(path = ["/auth/manage/users/findOne"])
    fun findOne(@RequestBody authParams: AuthParams): RUser {
        return authService.findOne(authParams)
    }

    // Endpoint to get a list of users with pagination
    @PostMapping(path = ["/auth/manage/users/findAll"])
    fun findAll(
        @RequestBody authParams: AuthParams,
        @RequestParam page: Int,
        @RequestParam itemsPerItem: Int
    ): MutableList<RUser> {
        return authService.findAll(authParams, page, itemsPerItem)
    }

    // Endpoint to add a permission to a user
    @PostMapping(path = ["/auth/manage/users/{email}/addPermission"])
    fun addPermission(
        @RequestBody permission: Perms,
        @PathVariable email: String
    ): UserModel {
        return authService.addPermission(permission, email)
    }

    // Endpoint to remove a permission from a user
    @PostMapping(path = ["/auth/manage/users/{email}/removePermission"])
    fun removePermission(
        @RequestBody permission: Perms,
        @PathVariable email: String
    ): UserModel {
        return authService.removePermission(permission, email)
    }

    // Endpoint to delete a user by email
    @DeleteMapping(path = ["/auth/manage/users/{email}/deleteUser"])
    fun deleteUser(@PathVariable email: String): Boolean {
        return authService.deleteUser(email)
    }

    // Endpoint to get a list of permissions
    @GetMapping(path = ["/auth/manage/perms/getList"])
    fun getPermissionList(): MutableList<Perms> {
        return authService.getPermissionList()
    }

    // Endpoint to get a list of roles
    @GetMapping(path = ["/auth/manage/roles/getList"])
    fun getRoles(): MutableList<AuthRole> {
        return authService.getRoles()
    }
}
