//===----------------------------------------------------------------------===//
//
// Chrome 145 ClientHello probe.
//
// Connects to https://tls.peet.ws/api/all (or any URL passed as argv[1])
// using `TLSConfiguration.chrome145Impersonation()` and writes the
// response body to stdout. Use the JSON to read the JA4 / JA3N /
// peetprint values produced by this fork's TLS handshake and compare
// against lexiforest's reference signatures
// (tests/signatures/chrome_142.0.7444.176.yaml in their repo).
//
// Acceptance criterion (DATADOME_BYPASS_PLAN.md §1c):
//   The peetprint and JA4 produced here should match Chrome 142+
//   on macOS. ja3n (normalised — extension order ignored) should
//   match exactly even with permutation enabled.
//
//===----------------------------------------------------------------------===//

import Foundation
import NIOCore
import NIOFoundationCompat
import NIOHTTP1
import NIOPosix
import NIOSSL

private final class CollectingHandler: ChannelInboundHandler {
    typealias InboundIn = HTTPClientResponsePart

    let promise: EventLoopPromise<Data>
    var buffer = Data()

    init(_ promise: EventLoopPromise<Data>) {
        self.promise = promise
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch self.unwrapInboundIn(data) {
        case .head:
            break
        case .body(var bb):
            if let chunk = bb.readData(length: bb.readableBytes) {
                self.buffer.append(chunk)
            }
        case .end:
            self.promise.succeed(self.buffer)
            context.channel.close(promise: nil)
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        self.promise.fail(error)
        context.channel.close(promise: nil)
    }
}

let arguments = CommandLine.arguments
let urlString = arguments.dropFirst().first ?? "https://tls.peet.ws/api/all"
guard let url = URL(string: urlString),
      let host = url.host
else {
    FileHandle.standardError.write(Data("invalid URL: \(urlString)\n".utf8))
    exit(2)
}

let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
defer { try? group.syncShutdownGracefully() }

let sslContext = try NIOSSLContext(configuration: .chrome145Impersonation())
let promise = group.next().makePromise(of: Data.self)

let bootstrap = ClientBootstrap(group: group)
    .channelInitializer { channel in
        channel.eventLoop.makeCompletedFuture {
            let tls = try NIOSSLClientHandler(context: sslContext, serverHostname: host)
            try channel.pipeline.syncOperations.addHandler(tls)
            try channel.pipeline.syncOperations.addHTTPClientHandlers()
            try channel.pipeline.syncOperations.addHandler(CollectingHandler(promise))
        }
    }

let port = url.port ?? 443
let path = url.path.isEmpty ? "/" : url.path

bootstrap.connect(host: host, port: port).flatMap { channel -> EventLoopFuture<Void> in
    var head = HTTPRequestHead(version: .http1_1, method: .GET, uri: path)
    head.headers = HTTPHeaders([
        ("Host", host),
        ("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"),
        ("Accept", "application/json,text/html;q=0.9,*/*;q=0.8"),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Connection", "close"),
    ])
    channel.write(HTTPClientRequestPart.head(head), promise: nil)
    return channel.writeAndFlush(HTTPClientRequestPart.end(nil))
}.cascadeFailure(to: promise)

let body = try promise.futureResult.wait()
FileHandle.standardOutput.write(body)
FileHandle.standardOutput.write(Data("\n".utf8))
