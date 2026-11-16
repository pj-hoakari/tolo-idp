package dev.usbharu.toloidp.logging

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.AppenderBase
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import org.slf4j.LoggerFactory
import kotlin.test.assertEquals

@Tag("unit")
class StructuredLoggingTests {
    @Test
    fun addsStructuredFieldsToSlf4jKeyValuePairs() {
        val logger = LoggerFactory.getLogger("test.structured") as Logger
        val previousLevel = logger.level
        val previousAdditive = logger.isAdditive
        val appender = CapturingAppender()
        appender.start()
        logger.addAppender(appender)
        logger.level = Level.INFO
        logger.isAdditive = false

        try {
            logger.structuredInfo(
                "Structured log sample",
                "event" to "login_completed",
                "tenant_id" to "tenant-a",
                "scope_count" to 2,
            )

            assertEquals("Structured log sample", appender.message)
            assertEquals("login_completed", appender.keyValuePairs["event"])
            assertEquals("tenant-a", appender.keyValuePairs["tenant_id"])
            assertEquals(2, appender.keyValuePairs["scope_count"])
        } finally {
            logger.detachAppender(appender)
            logger.level = previousLevel
            logger.isAdditive = previousAdditive
        }
    }

    @Test
    fun enhancerAddsKeyValuePairsToJsonMap() {
        val logger = LoggerFactory.getLogger("test.structured.enhancer") as Logger
        val previousLevel = logger.level
        val previousAdditive = logger.isAdditive
        val appender = CapturingAppender()
        appender.start()
        logger.addAppender(appender)
        logger.level = Level.INFO
        logger.isAdditive = false

        try {
            logger.structuredInfo(
                "Structured log sample",
                "event" to "login_completed",
                "tenant_id" to "tenant-a",
                "scope_count" to 2,
                "cache_hit" to true,
            )

            val jsonMap = mutableMapOf<String, Any>("message" to "Structured log sample")
            KeyValueLoggingEventEnhancer().enhanceJsonLogEntry(jsonMap, appender.event!!)

            assertEquals("login_completed", jsonMap["event"])
            assertEquals("tenant-a", jsonMap["tenant_id"])
            assertEquals(2, jsonMap["scope_count"])
            assertEquals(true, jsonMap["cache_hit"])
            assertEquals("Structured log sample", jsonMap["message"])
        } finally {
            logger.detachAppender(appender)
            logger.level = previousLevel
            logger.isAdditive = previousAdditive
        }
    }

    private class CapturingAppender : AppenderBase<ILoggingEvent>() {
        var event: ILoggingEvent? = null
            private set
        var message: String? = null
            private set
        var keyValuePairs: Map<String, Any?> = emptyMap()
            private set

        override fun append(eventObject: ILoggingEvent) {
            event = eventObject
            message = eventObject.formattedMessage
            keyValuePairs = eventObject.keyValuePairs.orEmpty().associate { it.key to it.value }
        }
    }
}
