package dev.usbharu.toloidp.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Profile
import org.springframework.data.jdbc.core.dialect.JdbcPostgresDialect

@Configuration(proxyBeanMethods = false)
@Profile("production", "dev-jvm", "dev-native")
class PostgresqlJdbcConfig {
    // AOT needs the dialect before configuration properties are bound. Supplying
    // it directly avoids initializing JdbcTemplate, DataSource, and Flyway.
    @Bean
    fun jdbcDialect(): JdbcPostgresDialect = JdbcPostgresDialect.INSTANCE
}
