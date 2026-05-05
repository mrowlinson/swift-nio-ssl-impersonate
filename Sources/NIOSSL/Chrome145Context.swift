//===----------------------------------------------------------------------===//
//
// Browser-impersonation TLS profiles.
//
// `swift-nio-ssl-impersonate` extends `apple/swift-nio-ssl` with the
// lexiforest BoringSSL patches that allow a TLS ClientHello to be
// emitted byte-for-byte compatible with a specific Chrome version.
// This file exposes the public factory(ies) on top of `TLSConfiguration`.
//
//===----------------------------------------------------------------------===//

/// Identifies a browser-impersonation profile recognised by the
/// patched BoringSSL inside this fork. Setting this on a
/// `TLSConfiguration` causes the `NIOSSLContext` constructor to apply
/// the matching cipher / extension / key-share / ALPS configuration.
public enum ChromeImpersonationProfile: Sendable, Hashable {
    /// Chrome 145 on macOS Tahoe shape: cipher list + extension order
    /// + permutation, X25519MLKEM768 post-quantum key share, ALPS new
    /// codepoint, GREASE, single-key-share offer.
    case chrome145
}

extension TLSConfiguration {
    /// Returns a `TLSConfiguration` that produces a TLS ClientHello
    /// shaped like Chrome 145 on macOS. Cipher order, extension order
    /// (with permutation), supported groups including X25519MLKEM768,
    /// signature algorithms, and ALPN (`h2`) are all set to match.
    ///
    /// The returned configuration:
    /// - sets `chromeImpersonation = .chrome145` so the SSL_CTX
    ///   constructor calls the patched BoringSSL setters
    /// - emits ALPN `h2` only — H2-only client
    /// - sets minimum TLS 1.2 / maximum TLS 1.3 to match Chrome
    public static func chrome145Impersonation() -> TLSConfiguration {
        var config = TLSConfiguration.makeClientConfiguration()
        config.minimumTLSVersion = .tlsv12
        config.maximumTLSVersion = .tlsv13
        config.applicationProtocols = ["h2"]

        // Chrome 145's cipher list, exact order:
        config.cipherSuiteValues = [
            .TLS_AES_128_GCM_SHA256,
            .TLS_AES_256_GCM_SHA384,
            .TLS_CHACHA20_POLY1305_SHA256,
            .TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            .TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            .TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            .TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            .TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            .TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            .TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            .TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            .TLS_RSA_WITH_AES_128_GCM_SHA256,
            .TLS_RSA_WITH_AES_256_GCM_SHA384,
            .TLS_RSA_WITH_AES_128_CBC_SHA,
            .TLS_RSA_WITH_AES_256_CBC_SHA,
        ]
        config.certificateVerification = .fullVerification
        config.renegotiationSupport = .none

        // Gates the patched-BoringSSL setters in `SSLContext.init`:
        // - SSL_CTX_set_permute_extensions(ctx, 1)        — Chrome 110+ randomises extensions
        // - SSL_CTX_set_extension_order(ctx, "...")       — Chrome 145 specific order
        // - SSL_CTX_set_key_shares_limit(ctx, 1)          — Chrome offers 1 key share
        // (without the lexiforest patches these calls compile to upstream
        // BoringSSL no-ops or compile errors — guarded by build-time check
        // in SSLContext.applyChromeImpersonation.)
        config.chromeImpersonation = .chrome145

        return config
    }
}
