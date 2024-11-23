package com.wanim.authservice.spec

import com.wanim.authservice.model.UserModel
import com.wanim.authservice.params.AuthParams
import jakarta.persistence.criteria.Predicate
import org.springframework.data.jpa.domain.Specification

class AuthSpec(val authParams: AuthParams) {

    var archived: Boolean? = null
    var deleted: Boolean? = null
    var public: Boolean? = null
    var email: String? = null
    var pk: Long? = null
    var id: String? = null

    fun ofSearch(): Specification<UserModel> {
        return Specification { root, query, builder ->
            var predicates: Predicate? = builder.conjunction()  // Başlangıçta boş bir conjunction (AND) ekliyoruz

            public?.let {
                predicates = builder.and(predicates, builder.equal(root.get<Boolean>("isPublic"), it))
            }

            archived?.let {
                predicates = builder.and(predicates, builder.equal(root.get<Boolean>("archived"), it))
            }

            deleted?.let {
                predicates = builder.and(predicates, builder.equal(root.get<Boolean>("deleted"), it))
            }

            id?.let {
                predicates = builder.and(predicates, builder.equal(root.get<String>("id"), it))
            }

            email?.let {
                predicates = builder.and(predicates, builder.equal(root.get<String>("email"), it))
            }

            pk?.let {
                predicates = builder.and(predicates, builder.equal(root.get<Long>("pk"), it))
            }

            authParams.username?.let {
                predicates = builder.and(predicates, builder.like(builder.lower(root.get("userName")), it.lowercase()))
            }


            authParams.email?.let {
                predicates = builder.and(
                    predicates,
                    builder.like(
                        builder.lower(root.get("email")),
                        it.lowercase()
                    )
                )
            }

            predicates
        }
    }


}