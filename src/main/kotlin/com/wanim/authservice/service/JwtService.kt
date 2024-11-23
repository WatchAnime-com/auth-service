package com.wanim.authservice.service

import com.wanim.authservice.model.UserModel
import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Keys
import org.springframework.stereotype.Service
import java.util.*
import java.util.function.Function
import javax.crypto.SecretKey

@Service
class JwtService {

    companion object {
        private var SECRET_KEY: String = buildString {
            append("7#^C@Bg9jdOBPI5uAxvF!NisWjO3ubwQF3dnZ8X6^H7jTR9CE29!vx!*cn*vLUn#KtJng7acyQxses4xYyJVugZ7%hf1U&%HyYbNZz!95T#Nsmk^rsh9h7&!aMcq4ks")
        }
        private const val TOKEN_VALIDITY = 1000 * 60 * 60 * 24 // 24 hours in milliseconds
    }

    private fun getSignKey(): SecretKey {
        return Keys.hmacShaKeyFor(SECRET_KEY.toByteArray())
    }

    fun <T> extractClaims(jwtToken: String?, claimsResolver: Function<Claims, T>): T {
        val claims = extractAllClaims(jwtToken)
        return claimsResolver.apply(claims)
    }

    fun extractClaims(jwtToken: String?): Claims {
        val claims = extractAllClaims(jwtToken)
        return claims
    }

    fun generateToken(userModel: UserModel): String {
        var tokenInfo = HashMap<String, Any>()
        tokenInfo["pk"] = userModel.pk
        return generateToken(tokenInfo, userModel.email.toString())
    }

    fun isTokenExpired(token: String?): Boolean {
        return extractExpiration(token).before(Date())
    }

    private fun extractExpiration(token: String?): Date {
        return extractClaims(token) { claims -> claims.expiration }
    }

    fun extractSubject(jwtToken: String?): String {
        return extractClaims(jwtToken) { claims -> claims.subject }
    }

    private fun extractAllClaims(token: String?): Claims {

        return Jwts.parser()
            .setSigningKey(getSignKey()) // Use the key returned by getSignKey
            .build()
            .parseClaimsJws(token)
            .body

    }

    private fun generateToken(claims: Map<String, Any>, subject: String): String {
        return Jwts.builder()
            .setClaims(claims)
            .setSubject(subject)
            .setIssuer("watchanim.com")
            .setIssuedAt(Date(System.currentTimeMillis()))
            .setExpiration(Date(System.currentTimeMillis() + TOKEN_VALIDITY)) // Örneğin: 24 saat
            .signWith(getSignKey())
            .compact()
    }

}