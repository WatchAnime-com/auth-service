package com.wanim.authservice.service.auth

import com.wanim.authservice.dto.CUser
import com.wanim.authservice.dto.LUser
import com.wanim.authservice.dto.RUser
import com.wanim.authservice.enums.AuthRole
import com.wanim.authservice.enums.Perms
import com.wanim.authservice.model.UserModel
import com.wanim.authservice.params.AuthParams

interface AuthService {
    fun registerUser(cUser: CUser): RUser
    fun login(lUser: LUser): RUser
    fun logoutAll()
    fun authUser(token: String): Boolean
    fun findOne(authParams: AuthParams): RUser
    fun findAll(authParams: AuthParams, page: Int, itemsPerItem: Int): MutableList<RUser>


    fun addPermission(permission: Perms, email: String): UserModel
    fun removePermission(permission: Perms, email: String): UserModel

    fun deleteUser(email:String): Boolean

    fun getPermissionList(): MutableList<Perms>

    fun getRoles(): MutableList<AuthRole>
}
