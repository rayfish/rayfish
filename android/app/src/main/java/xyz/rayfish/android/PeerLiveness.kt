package xyz.rayfish.android

import uniffi.ray_mobile.PeerConnState
import uniffi.ray_mobile.PeerInfo

/**
 * A live mesh connection to the peer exists right now.
 *
 * This is the honest signal for "connected", not for "can I reach it". Mobile
 * always runs the core in on-demand mode, so every link self-closes after the
 * idle timeout and a perfectly reachable peer drops to [PeerConnState.IDLE]
 * within a couple of minutes of the last packet. Use [isReachable] when the
 * question is whether the peer can be sent to.
 */
val PeerInfo.isActive: Boolean
    get() = state == PeerConnState.ACTIVE

/**
 * The peer is connected, or idle with no recent failed reach: worth dialing.
 * Only [PeerConnState.OFFLINE] means a reach attempt actually failed.
 */
val PeerInfo.isReachable: Boolean
    get() = state != PeerConnState.OFFLINE
