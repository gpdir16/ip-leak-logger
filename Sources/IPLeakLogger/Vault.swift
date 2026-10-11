import Foundation
import CryptoKit
import Security

struct AppSettings: Codable, Equatable {
    var intervalMs = 500        // 조회 주기
    var notify = true           // 알림 사용
    var sound = true            // 알림음
    var requireAuth = true      // 이벤트 열람/삭제/내보내기 시 인증
    var maskIP = false          // 화면의 IP 일부 가리기
    var retentionDays = 0       // 0 = 무기한

    init() {}

    // 설정 항목이 추가되어도 이전 저장본을 읽을 수 있도록 누락 키에 기본값을 쓴다.
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = AppSettings()
        intervalMs = try c.decodeIfPresent(Int.self, forKey: .intervalMs) ?? d.intervalMs
        notify = try c.decodeIfPresent(Bool.self, forKey: .notify) ?? d.notify
        sound = try c.decodeIfPresent(Bool.self, forKey: .sound) ?? d.sound
        requireAuth = try c.decodeIfPresent(Bool.self, forKey: .requireAuth) ?? d.requireAuth
        maskIP = try c.decodeIfPresent(Bool.self, forKey: .maskIP) ?? d.maskIP
        retentionDays = try c.decodeIfPresent(Int.self, forKey: .retentionDays) ?? d.retentionDays
    }
}

struct Secrets: Codable {
    var logKey: Data          // AES-256 로그 키
    var realIP: String?
    var settings = AppSettings()
}

/// 키체인 항목 하나에 키, 실IP, 설정을 JSON으로 모아 보관한다.
final class Vault {
    static let shared = Vault()
    private static let service = "com.local.ip-leak-logger"
    private static let account = "vault"

    private(set) var secrets: Secrets

    private init() {
        if let data = Vault.read(Vault.account),
           let stored = try? JSONDecoder().decode(Secrets.self, from: data) {
            secrets = stored
            return
        }
        // 이전 버전(항목 2개)에서 마이그레이션한다.
        let legacyKey = Vault.read("log-key")
        let key = (legacyKey?.count == 32) ? legacyKey! : SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
        let real = Vault.read("real-ip").flatMap { String(data: $0, encoding: .utf8) }
        secrets = Secrets(logKey: key, realIP: real)
        save()
        Vault.delete("log-key")
        Vault.delete("real-ip")
    }

    func update(_ change: (inout Secrets) -> Void) {
        change(&secrets)
        save()
    }

    private func save() {
        guard let data = try? JSONEncoder().encode(secrets) else { return }
        Vault.write(Vault.account, data)
    }

    // MARK: 키체인 저수준

    private static func baseQuery(_ account: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account]
    }

    private static func read(_ account: String) -> Data? {
        var query = baseQuery(account)
        query[kSecReturnData as String] = true
        var out: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &out) == errSecSuccess else { return nil }
        return out as? Data
    }

    private static func write(_ account: String, _ data: Data) {
        let base = baseQuery(account)
        let status = SecItemUpdate(base as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if status == errSecItemNotFound {
            var item = base
            item[kSecValueData as String] = data
            item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            SecItemAdd(item as CFDictionary, nil)
        }
    }

    private static func delete(_ account: String) {
        SecItemDelete(baseQuery(account) as CFDictionary)
    }
}
