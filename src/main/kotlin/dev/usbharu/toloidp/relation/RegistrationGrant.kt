package dev.usbharu.toloidp.relation

enum class RegistrationGrantType(val parameter: String) {
    INVITATION("invitation_token"),
    OWNERSHIP_CLAIM("ownership_claim_token"),
}

data class RegistrationGrant(
    val type: RegistrationGrantType,
    val token: String,
) {
    override fun toString(): String = "RegistrationGrant(type=$type)"
}

enum class RegistrationGrantVerdict {
    VALID,
    INVALID,
    UNAVAILABLE,
}

fun interface RegistrationGrantVerifier {
    fun verify(tenantId: String, grant: RegistrationGrant): RegistrationGrantVerdict
}
