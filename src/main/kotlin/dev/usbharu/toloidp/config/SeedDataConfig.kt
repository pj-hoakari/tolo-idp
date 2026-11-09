package dev.usbharu.toloidp.config

import dev.usbharu.toloidp.logging.structuredInfo
import dev.usbharu.toloidp.logging.structuredWarn
import dev.usbharu.toloidp.user.IdpUserDetailsManager
import dev.usbharu.toloidp.user.UserAccountRules
import dev.usbharu.toloidp.user.UserRegistrationService
import org.slf4j.LoggerFactory
import org.springframework.boot.ApplicationArguments
import org.springframework.boot.ApplicationRunner
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.transaction.annotation.Transactional

@Configuration
class SeedDataConfig {
    @Bean
    fun seedDataRunner(
        properties: IdpProperties,
        passwordEncoder: PasswordEncoder,
        userDetailsManager: IdpUserDetailsManager,
        userRegistrationService: UserRegistrationService,
    ): SeedDataRunner =
        SeedDataRunner(
            properties,
            passwordEncoder,
            userDetailsManager,
            userRegistrationService,
        )
}

/**
 * Loads development users from JSON and creates them with the same rules as the signup API.
 * Existing users are skipped only when the JSON entry completely matches the stored user.
 */
open class SeedDataRunner(
    private val properties: IdpProperties,
    private val passwordEncoder: PasswordEncoder,
    private val users: IdpUserDetailsManager,
    private val registration: UserRegistrationService,
    private val reader: SeedUserFileReader = SeedUserFileReader(),
) : ApplicationRunner {
    @Transactional
    override fun run(args: ApplicationArguments) {
        if (!properties.seed.enabled) {
            return
        }
        val resource = properties.seed.usersFile
        val configuredUsers = try {
            reader.read(resource)
        } catch (ex: IllegalStateException) {
            log.structuredWarn(
                "Seed users rejected",
                "event" to "seed_users_rejected",
                "failure_reason" to "users_file_invalid",
            )
            throw ex
        }
        val resolved = validate(configuredUsers)
        val plan = plan(resolved)

        var created = 0
        var skipped = 0
        plan.forEach { item ->
            when (item) {
                is SeedPlan.Create -> {
                    registration.create(item.user.tenantId, item.user.username, item.user.password, item.user.id)
                    created += 1
                    log.structuredInfo(
                        "Seed user created",
                        "event" to "seed_user_created",
                        "subject" to item.user.id,
                        "tenant_id" to item.user.tenantId,
                    )
                }
                is SeedPlan.Skip -> {
                    skipped += 1
                    log.structuredInfo(
                        "Seed user skipped",
                        "event" to "seed_user_skipped",
                        "subject" to item.user.id,
                        "tenant_id" to item.user.tenantId,
                    )
                }
            }
        }
        log.structuredInfo(
            "Seed users applied",
            "event" to "seed_users_applied",
            "created_count" to created,
            "skipped_count" to skipped,
        )
    }

    private fun validate(configuredUsers: List<SeedUser?>): List<ResolvedSeedUser> {
        val resolved = configuredUsers.mapIndexed { index, user ->
            if (user == null) {
                log.structuredWarn(
                    "Seed user rejected",
                    "event" to "seed_user_rejected",
                    "index" to index,
                    "failure_reason" to "user_required",
                )
                throw IllegalStateException("Seed users[$index]: user_required")
            }
            ResolvedSeedUser(
                index = index,
                id = requireField(user.id, index, "id_required"),
                tenantId = requireField(user.tenantId, index, "tenant_id_required"),
                username = requireField(user.username, index, "username_required"),
                password = requireField(user.password, index, "password_required"),
            ).also { entry ->
                if (!UserAccountRules.isValidUserId(entry.id)) reject(entry, "invalid_id")
                if (!UserAccountRules.isValidTenantId(entry.tenantId)) reject(entry, "invalid_tenant_id")
                if (!UserAccountRules.isValidUsername(entry.username)) reject(entry, "invalid_username")
                if (!UserAccountRules.isValidPassword(entry.password)) reject(entry, "invalid_password")
            }
        }
        rejectDuplicate(resolved, "duplicate_id", ResolvedSeedUser::id)
        rejectDuplicate(resolved, "duplicate_username") { "${it.tenantId}/${it.username}" }
        return resolved
    }

    private fun requireField(value: String?, index: Int, reason: String): String {
        if (value == null) {
            log.structuredWarn(
                "Seed user rejected",
                "event" to "seed_user_rejected",
                "index" to index,
                "failure_reason" to reason,
            )
            throw IllegalStateException("Seed users[$index]: $reason")
        }
        return value
    }

    private fun plan(entries: List<ResolvedSeedUser>): List<SeedPlan> =
        entries.map { entry ->
            if (users.userExists(entry.tenantId, entry.username)) {
                val existing = users.loadUserByUsername(entry.tenantId, entry.username)
                if (existing.id != entry.id) reject(entry, "id_mismatch")
                if (!existing.isEnabled) reject(entry, "user_disabled")
                if (existing.authorities.mapNotNull { it.authority }.toSet() != setOf("ROLE_USER")) {
                    reject(entry, "authorities_mismatch")
                }
                if (!passwordMatches(entry.password, existing.password)) reject(entry, "password_mismatch")
                SeedPlan.Skip(entry)
            } else {
                val existingById = runCatching { users.loadUserById(entry.id) }.getOrNull()
                if (existingById != null) reject(entry, "id_in_use")
                SeedPlan.Create(entry)
            }
        }

    private fun passwordMatches(rawPassword: String, encodedPassword: String?): Boolean {
        if (encodedPassword == null) {
            return false
        }
        return try {
            passwordEncoder.matches(rawPassword, encodedPassword)
        } catch (_: IllegalArgumentException) {
            false
        }
    }

    private fun rejectDuplicate(
        entries: List<ResolvedSeedUser>,
        reason: String,
        key: (ResolvedSeedUser) -> String,
    ) {
        val duplicates = entries.groupingBy(key).eachCount().filterValues { it > 1 }.keys.sorted()
        if (duplicates.isEmpty()) {
            return
        }
        log.structuredWarn(
            "Seed users rejected",
            "event" to "seed_users_rejected",
            "failure_reason" to reason,
            "duplicate_count" to duplicates.size,
        )
        throw IllegalStateException("Seed users contain duplicate $reason: ${duplicates.joinToString(",")}")
    }

    private fun reject(entry: ResolvedSeedUser, reason: String): Nothing {
        log.structuredWarn(
            "Seed user rejected",
            "event" to "seed_user_rejected",
            "index" to entry.index,
            "subject" to entry.id,
            "tenant_id" to entry.tenantId,
            "username" to entry.username,
            "failure_reason" to reason,
        )
        throw IllegalStateException("Seed users[${entry.index}]: $reason")
    }

    private data class ResolvedSeedUser(
        val index: Int,
        val id: String,
        val tenantId: String,
        val username: String,
        val password: String,
    )

    private sealed interface SeedPlan {
        data class Create(val user: ResolvedSeedUser) : SeedPlan

        data class Skip(val user: ResolvedSeedUser) : SeedPlan
    }

    private companion object {
        val log = LoggerFactory.getLogger(SeedDataRunner::class.java)
    }
}
