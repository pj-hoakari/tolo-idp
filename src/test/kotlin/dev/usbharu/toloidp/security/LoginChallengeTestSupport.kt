package dev.usbharu.toloidp.security

import org.springframework.http.MediaType
import org.springframework.mock.web.MockHttpSession
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.ResultActions
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.web.util.UriComponentsBuilder
import kotlin.test.assertEquals

const val LOGIN_PAGE = "http://localhost:3000/login"
const val LOGIN_ERROR_PAGE = "http://localhost:3000/auth/error"

fun MockMvc.challengeFrom(authorization: MockHttpServletRequestBuilder): String =
    loginChallenge(perform(authorization).andExpect(status().isFound).andReturn().response.redirectedUrl!!)

fun loginChallenge(location: String): String {
    val parameters = UriComponentsBuilder.fromUriString(location).build().queryParams
    assertEquals(LOGIN_PAGE, location.substringBefore('?'))
    assertEquals(setOf("challenge"), parameters.keys)
    return parameters.getFirst("challenge")!!
}

fun loginWithChallenge(
    challenge: String,
    username: String = "user-123",
    password: String = "password",
    session: MockHttpSession? = null,
): MockHttpServletRequestBuilder {
    val request = post("/api/login").contentType(MediaType.APPLICATION_JSON)
        .content("""{"username":"$username","password":"$password","challenge":"$challenge"}""")
    if (session != null) request.session(session)
    return request
}

fun MockMvc.loginWithChallengeSession(
    challenge: String,
    username: String = "user-123",
    password: String = "password",
    session: MockHttpSession? = null,
): MockHttpSession =
    perform(loginWithChallenge(challenge, username, password, session)).andExpect(status().isOk)
        .andReturn().request.session as MockHttpSession

fun resumeAuthorization(challenge: String, session: MockHttpSession? = null): MockHttpServletRequestBuilder {
    val request = get("/oauth2/authorize").queryParam("challenge", challenge)
    if (session != null) request.session(session)
    return request
}

fun assertLoginErrorPage(result: ResultActions) {
    val location = result.andExpect(status().isFound).andReturn().response.redirectedUrl!!
    assertEquals("$LOGIN_ERROR_PAGE?error=invalid_challenge", location)
}
