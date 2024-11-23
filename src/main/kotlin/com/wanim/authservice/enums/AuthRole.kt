package com.wanim.authservice.enums

import org.springframework.security.core.authority.SimpleGrantedAuthority

// Enum class representing roles and their associated permissions
enum class AuthRole(
    val permissions: Set<Perms>
) {
    // User role - limited permissions
    USER(setOf(
        Perms.VIDEO_VIEW,
        Perms.COMMENT,
        Perms.LIKE,
        Perms.DISLIKE,
        Perms.RATE
    )),

    // Editor role - can edit videos and playlists
    EDITOR(setOf(
        Perms.VIDEO_VIEW,
        Perms.VIDEO_EDIT,
        Perms.VIDEO_ADD,
        Perms.VIDEO_DELETE,
        Perms.PLAYLIST_CREATE,
        Perms.PLAYLIST_EDIT,
        Perms.PLAYLIST_SHARE
    )),

    // Translator role - can edit subtitles
    TRANSLATOR(setOf(
        Perms.SUBTITLE_CREATE,
        Perms.SUBTITLE_EDIT,
        Perms.SUBTITLE_SYNC
    )),

    // Admin role - full permissions
    ADMIN(setOf(
        // Video Management permissions
        Perms.VIDEO_ADD,
        Perms.VIDEO_DELETE,
        Perms.VIDEO_EDIT,
        Perms.VIDEO_VIEW,

        // Subtitle Management permissions
        Perms.SUBTITLE_CREATE,
        Perms.SUBTITLE_DELETE,
        Perms.SUBTITLE_EDIT,
        Perms.SUBTITLE_SYNC,

        // Playlist Management permissions
        Perms.PLAYLIST_CREATE,
        Perms.PLAYLIST_DELETE,
        Perms.PLAYLIST_EDIT,
        Perms.PLAYLIST_SHARE,

        // User Interaction permissions
        Perms.COMMENT,
        Perms.LIKE,
        Perms.DISLIKE,
        Perms.RATE,
        Perms.REPORT,

        // Admin specific permissions
        Perms.ADMIN_ADD_PERM,
        Perms.ADMIN_REMOVE_PERM,
        Perms.ADMIN_GET_PERMS,
        Perms.ADMIN_GET_ROLES,
        Perms.ADMIN_SET_ROLE
    ));

    // Method to get authorities for the role
    fun getAuth(): List<SimpleGrantedAuthority> {
        // Map permissions to SimpleGrantedAuthority
        val authorities = permissions.map { SimpleGrantedAuthority("ROLE_"+it.name) }.toMutableList()

        // Add role-specific authority
        authorities.add(SimpleGrantedAuthority("ROLE_${this.name}"))

        return authorities
    }
}
