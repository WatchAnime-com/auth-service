package com.wanim.authservice.enums

enum class Perms(s: String) {

    // Video Management permissions - for actions like uploading, deleting, and editing videos
    VIDEO_ADD("video:add"),
    VIDEO_DELETE("video:delete"),
    VIDEO_EDIT("video:edit"),
    VIDEO_VIEW("video:view"),

    // Subtitle Management permissions - for actions like creating, editing, and deleting subtitles
    SUBTITLE_CREATE("subtitle:create"),
    SUBTITLE_DELETE("subtitle:delete"),
    SUBTITLE_EDIT("subtitle:edit"),
    SUBTITLE_SYNC("subtitle:sync"),

    // Playlist Management permissions - for actions related to creating and modifying playlists
    PLAYLIST_CREATE("playlist:create"),
    PLAYLIST_DELETE("playlist:delete"),
    PLAYLIST_EDIT("playlist:edit"),
    PLAYLIST_SHARE("playlist:share"),

    // User Interaction permissions - actions like commenting, liking, and rating videos
    COMMENT("user:comment"),
    LIKE("user:like"),
    DISLIKE("user:dislike"),
    RATE("user:rate"),
    REPORT("user:report"),


    // ADMIN

    ADMIN_ADD_PERM("admin:addPermission"),
    ADMIN_REMOVE_PERM("admin:removePermission"),
    ADMIN_GET_PERMS("admin:getPermissions"),
    ADMIN_GET_ROLES("admin:getRoles"),
    ADMIN_SET_ROLE("admin:setRole");


}