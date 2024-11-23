package com.wanim.authservice.mapper

import com.wanim.authservice.dto.RUser
import com.wanim.authservice.model.UserModel
import org.springframework.stereotype.Service

@Service
class AuthMapper {

    fun createResponse(userModel: UserModel): RUser{
        return RUser().apply {
            this.email = userModel.email
            this.username = userModel.username
        }
    }

}

