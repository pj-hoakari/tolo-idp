package dev.usbharu.toloidp.relation

/**
 * tenant / event の認可判定に必要な所属情報を取得する境界。
 */
interface RelationService {
    /**
     * [tenantId] における [userId] の所属情報を返す。
     *
     * Token Exchange の event 認可で使う event 単位の所属情報も含める。
     */
    fun getMembership(tenantId: String, userId: String): TenantMembership

    fun getMembership(tenantId: String, userId: String, eventId: String): TenantMembership =
        getMembership(tenantId, userId)
}
