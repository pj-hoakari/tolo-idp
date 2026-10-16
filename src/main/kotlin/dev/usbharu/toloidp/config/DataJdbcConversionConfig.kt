package dev.usbharu.toloidp.config

import dev.usbharu.toloidp.relation.RelationMembershipCache
import dev.usbharu.toloidp.relation.TenantMembership
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.convert.converter.Converter
import org.springframework.data.convert.ReadingConverter
import org.springframework.data.convert.WritingConverter
import org.springframework.data.jdbc.core.convert.JdbcCustomConversions
import org.springframework.data.relational.core.mapping.event.AfterConvertCallback
import tools.jackson.databind.ObjectMapper
import tools.jackson.module.kotlin.readValue

@Configuration
class DataJdbcConversionConfig {
    @Bean
    fun jdbcCustomConversions(objectMapper: ObjectMapper): JdbcCustomConversions =
        JdbcCustomConversions(
            listOf(
                TenantMembershipReadingConverter(objectMapper),
                TenantMembershipWritingConverter(objectMapper),
            ),
        )

    @Bean
    fun relationMembershipCacheAfterConvertCallback(): AfterConvertCallback<RelationMembershipCache> =
        AfterConvertCallback { cache ->
            cache.apply { isNewEntity = false }
        }
}

@ReadingConverter
class TenantMembershipReadingConverter(
    private val objectMapper: ObjectMapper,
) : Converter<String, TenantMembership> {
    override fun convert(source: String): TenantMembership =
        objectMapper.readValue(source)
}

@WritingConverter
class TenantMembershipWritingConverter(
    private val objectMapper: ObjectMapper,
) : Converter<TenantMembership, String> {
    override fun convert(source: TenantMembership): String =
        objectMapper.writeValueAsString(source)
}
