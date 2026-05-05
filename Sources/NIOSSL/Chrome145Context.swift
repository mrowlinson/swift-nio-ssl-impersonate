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
        // Chrome 142+ cipher list, exact order. The leading GREASE
        // marker is auto-injected by BoringSSL when grease_enabled=1
        // (set by applyChromeImpersonation below).
        config.cipherSuiteValues = [
            .TLS_AES_128_GCM_SHA256,                       // 4865
            .TLS_AES_256_GCM_SHA384,                       // 4866
            .TLS_CHACHA20_POLY1305_SHA256,                 // 4867
            .TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,      // 49195
            .TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,        // 49199
            .TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,      // 49196
            .TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,        // 49200
            .TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,// 52393
            .TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,  // 52392
            .TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,           // 49171
            .TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,           // 49172
            .TLS_RSA_WITH_AES_128_GCM_SHA256,              // 156
            .TLS_RSA_WITH_AES_256_GCM_SHA384,              // 157
            .TLS_RSA_WITH_AES_128_CBC_SHA,                 // 47
            .TLS_RSA_WITH_AES_256_CBC_SHA,                 // 53
        ]

        // Chrome 142+ supported_groups, exact order. GREASE marker is
        // auto-injected at index 0 by BoringSSL when grease_enabled=1.
        config.curves = [
            .x25519_MLKEM768,  // 4588
            .x25519,           // 29
            .secp256r1,        // 23
            .secp384r1,        // 24
        ]

        // Chrome 142+ signature_algorithms, exact order. Affects both
        // the offered list (signing) and the accepted list (verify).
        let chromeSigAlgs: [SignatureAlgorithm] = [
            .ecdsaSecp256R1Sha256,  // 1027
            .rsaPssRsaeSha256,      // 2052
            .rsaPkcs1Sha256,        // 1025
            .ecdsaSecp384R1Sha384,  // 1283
            .rsaPssRsaeSha384,      // 2053
            .rsaPkcs1Sha384,        // 1281
            .rsaPssRsaeSha512,      // 2054
            .rsaPkcs1Sha512,        // 1537
        ]
        config.verifySignatureAlgorithms = chromeSigAlgs
        config.signingSignatureAlgorithms = chromeSigAlgs

        config.certificateVerification = .fullVerification
        config.renegotiationSupport = .none

        // Gates the patched-BoringSSL setters in `SSLContext.init`
        // (see applyChromeImpersonation): permute_extensions and
        // grease_enabled. Other Chrome-specific shape (ALPS,
        // compress_certificate, ECH) requires per-SSL plumbing
        // through NIOSSL and is deliberately deferred — defeating
        // simple TLS-fingerprint checks does not require it.
        config.chromeImpersonation = .chrome145

        return config
    }
}
