package dev.usbharu.toloidp.config

import org.springframework.beans.factory.config.BeanFactoryPostProcessor
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import java.util.TimeZone

/**
 * The schema stores expiry columns as timestamp without time zone. pgjdbc converts
 * Instant values through the JVM default zone, so every instance must use one zone.
 * Set UTC before any datasource bean is created.
 */
object UtcTimeZone {
    fun configure() {
        TimeZone.setDefault(TimeZone.getTimeZone("UTC"))
    }
}

@Configuration
class TimeZoneConfig {
    @Bean
    fun utcTimeZonePostProcessor(): BeanFactoryPostProcessor = object : BeanFactoryPostProcessor {
        override fun postProcessBeanFactory(beanFactory: ConfigurableListableBeanFactory) {
            UtcTimeZone.configure()
        }
    }
}
