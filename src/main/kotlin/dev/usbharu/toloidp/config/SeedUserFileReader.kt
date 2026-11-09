package dev.usbharu.toloidp.config

import org.springframework.core.io.Resource
import tools.jackson.core.JacksonException
import tools.jackson.core.StreamReadFeature
import tools.jackson.databind.DeserializationFeature
import tools.jackson.databind.json.JsonMapper
import tools.jackson.module.kotlin.KotlinModule
import java.io.IOException

/**
 * Reads the development seed JSON strictly. Values are intentionally not included in errors
 * because the file contains raw passwords.
 */
class SeedUserFileReader {
    private val jsonMapper: JsonMapper = JsonMapper.builder()
        .addModule(KotlinModule.Builder().build())
        .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
        .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
        .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
        .build()

    fun read(resource: Resource): List<SeedUser?> {
        if (!resource.exists()) {
            throw IllegalStateException("Seed users file does not exist: ${resource.description}")
        }
        val file = try {
            resource.inputStream.use { jsonMapper.readValue(it, SeedUsersFile::class.java) }
        } catch (ex: JacksonException) {
            val location = ex.location
            val position = if (location == null) {
                ""
            } else {
                " at line ${location.lineNr}, column ${location.columnNr}"
            }
            throw IllegalStateException("Failed to parse seed users file '${resource.description}'$position")
        } catch (_: IOException) {
            throw IllegalStateException("Failed to read seed users file '${resource.description}'")
        } catch (_: RuntimeException) {
            throw IllegalStateException("Failed to parse seed users file '${resource.description}'")
        }
        return file.users
            ?: throw IllegalStateException("Seed users file '${resource.description}' must contain a users array")
    }
}
