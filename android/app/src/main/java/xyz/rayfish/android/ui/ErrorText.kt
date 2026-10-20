package xyz.rayfish.android.ui

import uniffi.ray_mobile.RayException
import uniffi.ray_mobile.errorMessage

/**
 * The error in words for a toast. A core error's generated `message` is its
 * fields (`v1=...`), so it comes from the core's own wording instead.
 */
val Throwable.userMessage: String
    get() = if (this is RayException) errorMessage(this) else message.orEmpty()
