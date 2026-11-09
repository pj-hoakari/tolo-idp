package dev.usbharu.toloidp.config

data class SeedUsersFile(
    val users: List<SeedUser?>? = null,
)

data class SeedUser(
    val id: String? = null,
    val tenantId: String? = null,
    val username: String? = null,
    val password: String? = null,
)
