package com.wanim.authservice.repo

import com.wanim.authservice.model.UserModel
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.JpaSpecificationExecutor
import java.util.UUID

interface AuthRepo : JpaRepository<UserModel,UUID> , JpaSpecificationExecutor<UserModel>