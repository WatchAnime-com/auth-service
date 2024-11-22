package com.wanim.authservice.dto

import com.wanim.authservice.enums.AuthRole

class RUser {
    var username: String? = null
    var email: String? = null
    var token: String? = null
    var roles: List<String>? = null
}