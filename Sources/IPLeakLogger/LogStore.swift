import Foundation
import CryptoKit

struct LogEntry: Codable, Identifiable {
    var id = UUID()
    var date: Date
    var kind: String          // start / changed / exposed / offline / online / realip / cleared
    var from: String?
    var to: String?
    var endpoint: String?     // 변경을 관측한 엔드포인트
    var fromCountry: String?
    var toCountry: String?
    var prev: String?         // 직전 레코드의 SHA-256(해시 체인)
}

/// 항목 단위 AES-256-GCM 암호화 로그. 해시 체인으로 삭제/변조를 감지한다.
/// 레코드 형식: [4바이트 길이(빅엔디언)][AES-GCM combined]
final class LogStore {
    private let vault = Vault.shared
    private let fileURL: URL
    private var lastHash: String?
    private(set) var integrityOK = true

    init() {
        let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("IPLeakLogger", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o700])
        fileURL = dir.appendingPathComponent("events.log")
        _ = loadAll()
    }

    private var key: SymmetricKey { SymmetricKey(data: vault.secrets.logKey) }

    private static func hash(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private func seal(_ entry: LogEntry) -> Data? {
        guard let plain = try? JSONEncoder().encode(entry),
              let box = try? AES.GCM.seal(plain, using: key),
              let combined = box.combined else { return nil }
        return combined
    }

    private static func frame(_ combined: Data) -> Data {
        var record = Data()
        var len = UInt32(combined.count).bigEndian
        withUnsafeBytes(of: &len) { record.append(contentsOf: $0) }
        record.append(combined)
        return record
    }

    private func writeFile(_ data: Data) {
        try? data.write(to: fileURL, options: [.atomic, .completeFileProtection])
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
    }

    func append(_ entry: LogEntry) {
        var e = entry
        e.prev = lastHash
        guard let combined = seal(e) else { return }
        let record = Self.frame(combined)
        if let handle = try? FileHandle(forWritingTo: fileURL) {
            defer { try? handle.close() }
            _ = try? handle.seekToEnd()
            try? handle.write(contentsOf: record)
        } else {
            writeFile(record)
        }
        lastHash = Self.hash(combined)
    }

    /// 전체를 복호화하고 체인을 검증한다. 오래된 순으로 반환한다.
    func loadAll() -> [LogEntry] {
        guard let data = try? Data(contentsOf: fileURL) else {
            lastHash = nil
            integrityOK = true
            return []
        }
        var entries: [LogEntry] = []
        var offset = 0
        var prevHash: String?
        var chainStarted = false
        var ok = true
        while offset + 4 <= data.count {
            let len = data[offset..<offset + 4].reduce(0) { ($0 << 8) | Int($1) }
            offset += 4
            guard offset + len <= data.count else { ok = false; break }
            let chunk = Data(data[offset..<offset + len])
            offset += len
            if let box = try? AES.GCM.SealedBox(combined: chunk),
               let plain = try? AES.GCM.open(box, using: key),
               let entry = try? JSONDecoder().decode(LogEntry.self, from: plain) {
                if let p = entry.prev {
                    chainStarted = true
                    if p != prevHash { ok = false }
                } else if chainStarted {
                    ok = false
                }
                entries.append(entry)
            } else {
                ok = false
            }
            prevHash = Self.hash(chunk)
        }
        lastHash = prevHash
        integrityOK = ok
        return entries
    }

    /// 보관 기간이 지난 항목을 제거하고 체인을 다시 만든다.
    func purge(olderThan cutoff: Date) -> Bool {
        let all = loadAll()
        let kept = all.filter { $0.date >= cutoff }
        guard kept.count != all.count, integrityOK else { return false }
        var out = Data()
        var prev: String?
        for var e in kept {
            e.prev = prev
            guard let combined = seal(e) else { continue }
            out.append(Self.frame(combined))
            prev = Self.hash(combined)
        }
        writeFile(out)
        lastHash = prev
        return true
    }

    /// 파일을 지우고 키를 교체해, 남아 있을 수 있는 조각도 복호화할 수 없게 한다.
    func clear() {
        try? FileManager.default.removeItem(at: fileURL)
        vault.update { $0.logKey = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) } }
        lastHash = nil
        integrityOK = true
    }
}
