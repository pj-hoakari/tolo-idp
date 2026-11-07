package dev.usbharu.toloidp.security

const val TOKEN_USE_TENANT_ACCESS = "tenant_access"
const val TOKEN_USE_EVENT_ACCESS = "event_access"
const val TOKEN_USE_REGISTRATION = "registration"
const val TOKEN_EXCHANGE_TRANSITION_TENANT_TO_EVENT = "tenant_access:event_access"
const val ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
const val JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"
const val REQUEST_ATTRIBUTE_TOKEN_AUDIT = "toloIdp.tokenAudit"
const val DEVICE_GRANT_ID_ATTRIBUTE = "toloIdp.deviceGrantId"
const val EDGE_DEVICE_ID_PARAMETER = "edge_device_id"
const val STAFF_TOKEN_HEADER = "X-Tolo-Staff-Token"
const val LOGIN_CHALLENGE_PARAMETER = "challenge"
