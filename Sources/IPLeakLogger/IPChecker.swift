import Foundation
import Network

struct IPResult {
    let endpoint: String   // 호스트 문자열(예: 1.1.1.1)
    let ip: String
    let latencyMs: Int
    let country: String?   // 트레이스의 loc 값(ISO 3166 alpha-2)
}

/// 연결 재사용 여부를 확인하기 위한 델리게이트
private final class ReuseProbe: NSObject, URLSessionTaskDelegate {
    var reused = false
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    didFinishCollecting metrics: URLSessionTaskMetrics) {
        if metrics.transactionMetrics.contains(where: { $0.isReusedConnection }) { reused = true }
    }
}

/// Cloudflare 트레이스 엔드포인트(1.1.1.1)로 외부 IP를 조회한다.
/// IP 리터럴만 사용해 DNS 경로 차이나 IPv4/IPv6 혼선으로 인한 오탐을 막는다.
final class IPChecker {
    static let endpoints: [URL] = [
        URL(string: "https://1.1.1.1/cdn-cgi/trace")!,
    ]
    private var cursor = 0

    /// 호출할 때마다 엔드포인트를 번갈아 사용한다.
    func nextEndpoint() -> URL {
        let url = Self.endpoints[cursor % Self.endpoints.count]
        cursor += 1
        return url
    }

    /// 요청마다 새 세션(=새 연결)을 쓴다.
    /// HTTP/2는 `Connection: close`를 무시하고 연결을 재사용하므로, 경로가 바뀐 뒤에도
    /// 옛 경로로 열린 연결이 이전 IP를 계속 보고하는 오탐이 생긴다. 재사용된 응답은 폐기한다.
    func fetch(from url: URL) async -> IPResult? {
        let config = URLSessionConfiguration.ephemeral
        config.urlCache = nil
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.waitsForConnectivity = false
        let probe = ReuseProbe()
        let session = URLSession(configuration: config, delegate: probe, delegateQueue: nil)
        defer { session.invalidateAndCancel() }

        var request = URLRequest(url: url)
        request.timeoutInterval = 2
        let started = Date()
        guard let (data, response) = try? await session.data(for: request),
              (response as? HTTPURLResponse)?.statusCode == 200,
              !probe.reused,
              let body = String(data: data, encoding: .utf8) else { return nil }
        let latency = Int(Date().timeIntervalSince(started) * 1000)
        var fields: [String: String] = [:]
        for line in body.split(separator: "\n") {
            let parts = line.split(separator: "=", maxSplits: 1).map(String.init)
            if parts.count == 2 { fields[parts[0]] = parts[1].trimmingCharacters(in: .whitespaces) }
        }
        guard let value = fields["ip"],
              IPv4Address(value) != nil || IPv6Address(value) != nil else { return nil }
        return IPResult(endpoint: url.host ?? "?", ip: value, latencyMs: latency, country: fields["loc"])
    }
}
