package dev.usbharu.toloidp.config

import dev.usbharu.toloidp.relation.HttpRelationService
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.aot.hint.MemberCategory
import org.springframework.aot.hint.RuntimeHints
import org.springframework.aot.hint.predicate.RuntimeHintsPredicates

class ToloIdpRuntimeHintsTest {

    private val hints = RuntimeHints().also { ToloIdpRuntimeHints().registerHints(it, null) }

    @Test
    fun `registers reflection hints for the relation API response and its nested types`() {
        val types = listOf(
            HttpRelationService.MembershipsResponse::class.java,
            HttpRelationService.MembershipNode::class.java,
            HttpRelationService.EventRoleNode::class.java,
        )

        types.forEach { type ->
            assertThat(
                RuntimeHintsPredicates.reflection()
                    .onType(type)
                    .withMemberCategory(MemberCategory.INVOKE_DECLARED_CONSTRUCTORS),
            ).describedAs("reflection hint for %s", type.name).accepts(hints)
        }
    }

    @Test
    fun `registers reflection and resource hints for the seed users file`() {
        listOf(SeedUsersFile::class.java, SeedUser::class.java).forEach { type ->
            assertThat(
                RuntimeHintsPredicates.reflection()
                    .onType(type)
                    .withMemberCategory(MemberCategory.INVOKE_DECLARED_CONSTRUCTORS),
            ).describedAs("reflection hint for %s", type.name).accepts(hints)
        }
        assertThat(RuntimeHintsPredicates.resource().forResource("seed/users.json")).accepts(hints)
    }
}
