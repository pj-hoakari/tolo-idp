package dev.usbharu.toloidp.scope

/** OAuth2 scope names shared by issuance policy, client registration and discovery. */
object IdpScopes {
    const val OPENID = "openid"
    const val TENANT_READ = "tenant.read"
    const val TENANT_WRITE = "tenant.write"
    const val TENANT_CLAIM = "tenant.claim"
    const val EVENTS_READ = "events.read"
    const val EVENTS_MANAGE = "events.manage"
    const val EVENTS_OPERATE = "events.operate"
    const val EVENTS_REPORT = "events.report"

    val IDENTITY: Set<String> = setOf(OPENID)
    val SUPPORTED: Set<String> = linkedSetOf(
        OPENID,
        TENANT_READ,
        TENANT_WRITE,
        TENANT_CLAIM,
        EVENTS_READ,
        EVENTS_MANAGE,
        EVENTS_OPERATE,
        EVENTS_REPORT,
    )
}
