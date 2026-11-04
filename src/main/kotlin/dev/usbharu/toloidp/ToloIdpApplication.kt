package dev.usbharu.toloidp

import dev.usbharu.toloidp.config.ToloIdpRuntimeHints
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import dev.usbharu.toloidp.config.UtcTimeZone
import org.springframework.context.annotation.ImportRuntimeHints

@SpringBootApplication
@ImportRuntimeHints(ToloIdpRuntimeHints::class)
class ToloIdpApplication

fun main(args: Array<String>) {
    UtcTimeZone.configure()
    runApplication<ToloIdpApplication>(*args)
}
