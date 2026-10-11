import Foundation
import Network
import SwiftUI
import AppKit
import Combine
import LocalAuthentication
import UserNotifications
import ServiceManagement

struct EndpointState: Identifiable {
    var id: String { host }
    let host: String
    var ip: String?
    var country: String?
    var latencyMs: Int?
    var updated: Date?
}

// MARK: 표시 헬퍼

/// 국가 코드를 국기 이모지로 바꾼다. 알 수 없는 값은 지구본으로 표시한다.
func flagEmoji(_ code: String?) -> String {
    guard let code = code?.uppercased(), code.count == 2,
          code.allSatisfy({ $0.isASCII && $0.isLetter }), code != "XX" else { return "🌐" }
    return code.unicodeScalars.compactMap { UnicodeScalar(127397 + $0.value) }.map { String($0) }.joined()
}

func countryName(_ code: String?) -> String {
    guard let code, code.count == 2, code.uppercased() != "XX" else { return "Unknown" }
    if code.uppercased() == "T1" { return "Tor network" }
    return Locale(identifier: "en_US").localizedString(forRegionCode: code) ?? code
}

/// 화면 표시용으로 IP 뒷부분을 가린다.
func maskedIP(_ ip: String) -> String {
    if ip.contains(":") {
        return (ip.split(separator: ":").first.map(String.init) ?? "") + ":••••"
    }
    let parts = ip.split(separator: ".")
    guard parts.count == 4 else { return ip }
    return "\(parts[0]).\(parts[1]).•••.•••"
}

@MainActor
final class Monitor: ObservableObject {
    static let shared = Monitor()

    enum Status { case starting, ok, changed, exposed, offline }

    @Published var status: Status = .starting
    @Published var currentIP: String?
    @Published var currentCountry: String?
    @Published var stableSince: Date?
    @Published var lastCheck: Date?
    @Published var events: [LogEntry] = []
    @Published var realIP: String?
    @Published var launchAtLogin = false
    @Published var integrityOK = true
    @Published var unlockedUntil: Date?
    @Published var endpoints: [EndpointState] =
        IPChecker.endpoints.map { EndpointState(host: $0.host ?? "?") }
    @Published var settings: AppSettings {
        didSet {
            guard settings != oldValue else { return }
            vault.update { $0.settings = settings }
            if settings.retentionDays != oldValue.retentionDays { purgeExpired() }
        }
    }

    private let vault = Vault.shared
    private let checker = IPChecker()
    private let store = LogStore()
    private let pathMonitor = NWPathMonitor()

    private var seq = 0
    private var lastApplied = 0
    private var failures = 0
    private let offlineThreshold = 3   // 연속 실패 횟수

    private init() {
        settings = vault.secrets.settings
        realIP = vault.secrets.realIP
        launchAtLogin = SMAppService.mainApp.status == .enabled
        events = Array(store.loadAll().reversed().prefix(200))
        integrityOK = store.integrityOK
        purgeExpired()
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }

        // 네트워크 경로 변경 시 즉시 재조회
        pathMonitor.pathUpdateHandler = { [weak self] _ in
            Task { @MainActor in self?.check() }
        }
        pathMonitor.start(queue: DispatchQueue(label: "path-monitor"))

        // 설정된 주기마다 조회 (응답을 기다리지 않고 틱마다 발사, 순번으로 오래된 응답은 무시)
        Task { [weak self] in
            while !Task.isCancelled {
                self?.check()
                let ms = self?.settings.intervalMs ?? 500
                try? await Task.sleep(nanoseconds: UInt64(max(100, ms)) * 1_000_000)
            }
        }
        // 보관 기간 정리는 1시간마다
        Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 3_600_000_000_000)
                self?.purgeExpired()
            }
        }
    }

    // MARK: 표시용

    var iconName: String {
        switch status {
        case .starting: return "network"
        case .ok: return "checkmark.shield.fill"
        case .changed: return "exclamationmark.triangle.fill"
        case .exposed: return "exclamationmark.octagon.fill"
        case .offline: return "wifi.slash"
        }
    }

    var statusColor: Color {
        switch status {
        case .starting, .offline: return .gray
        case .ok: return .green
        case .changed: return .orange
        case .exposed: return .red
        }
    }

    var statusTitle: String {
        switch status {
        case .starting: return "Checking…"
        case .ok: return "IP stable"
        case .changed: return "IP changed"
        case .exposed: return "Real IP exposed"
        case .offline: return "Offline"
        }
    }

    /// 메뉴바 아이콘. 경고 상태는 색을 입힌 비템플릿 이미지로 표시한다.
    var menuBarImage: NSImage {
        let base = NSImage(systemSymbolName: iconName, accessibilityDescription: statusTitle)!
        switch status {
        case .changed, .exposed:
            let color: NSColor = status == .exposed ? .systemRed : .systemOrange
            let img = base.withSymbolConfiguration(.init(paletteColors: [color])) ?? base
            img.isTemplate = false
            return img
        default:
            base.isTemplate = true
            return base
        }
    }

    func display(_ ip: String) -> String { settings.maskIP ? maskedIP(ip) : ip }

    // MARK: 조회

    private func check() {
        seq += 1
        let id = seq
        let url = checker.nextEndpoint()
        Task {
            let result = await checker.fetch(from: url)
            apply(id: id, host: url.host ?? "?", result: result)
        }
    }

    private func apply(id: Int, host: String, result: IPResult?) {
        guard id > lastApplied else { return }
        lastApplied = id
        lastCheck = Date()

        guard let result else {
            failures += 1
            if failures == offlineThreshold && status != .offline {
                status = .offline
                record(kind: "offline", from: currentIP, to: nil, endpoint: nil,
                       fromCountry: currentCountry, toCountry: nil,
                       alert: "Network unreachable. Check your VPN/connection.")
            }
            return
        }
        failures = 0
        let ip = result.ip
        let country = result.country

        // 엔드포인트별 직전 값과 비교한다.
        var previous: String?
        var previousCountry: String?
        if let i = endpoints.firstIndex(where: { $0.host == host }) {
            previous = endpoints[i].ip
            previousCountry = endpoints[i].country
            endpoints[i].ip = ip
            endpoints[i].country = country
            endpoints[i].latencyMs = result.latencyMs
            endpoints[i].updated = Date()
        }
        currentIP = ip
        currentCountry = country

        if status == .offline {
            status = .ok
            record(kind: "online", from: nil, to: ip, endpoint: host, fromCountry: nil, toCountry: country, alert: nil)
        }

        guard let previous else {
            // 이 엔드포인트의 첫 관측
            stableSince = Date()
            if let real = realIP, ip == real {
                status = .exposed
                record(kind: "exposed", from: nil, to: ip, endpoint: host, fromCountry: nil, toCountry: country,
                       alert: "Your real IP is exposed: \(display(ip)) (\(countryName(country)))")
            } else if status == .starting {
                status = .ok
                record(kind: "start", from: nil, to: ip, endpoint: host, fromCountry: nil, toCountry: country, alert: nil)
            }
            return
        }

        if ip != previous {
            stableSince = Date()
            if let real = realIP, ip == real {
                status = .exposed
                record(kind: "exposed", from: previous, to: ip, endpoint: host,
                       fromCountry: previousCountry, toCountry: country,
                       alert: "Your real IP is exposed: \(display(ip)) (\(countryName(country)))")
            } else {
                status = .changed
                record(kind: "changed", from: previous, to: ip, endpoint: host,
                       fromCountry: previousCountry, toCountry: country,
                       alert: "IP changed: \(display(previous)) → \(display(ip)) (\(countryName(country)))")
            }
        }
    }

    private func record(kind: String, from: String?, to: String?, endpoint: String?,
                        fromCountry: String?, toCountry: String?, alert: String?) {
        let entry = LogEntry(date: Date(), kind: kind, from: from, to: to, endpoint: endpoint,
                             fromCountry: fromCountry, toCountry: toCountry)
        store.append(entry)
        events.insert(entry, at: 0)
        if events.count > 200 { events.removeLast() }
        if let alert, settings.notify { notify(alert) }
    }

    private func notify(_ message: String) {
        let content = UNMutableNotificationContent()
        content.title = "IP Leak Logger"
        content.body = message
        if settings.sound { content.sound = .defaultCritical }
        UNUserNotificationCenter.current().add(
            UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil))
    }

    // MARK: 인증

    var isUnlocked: Bool {
        !settings.requireAuth || (unlockedUntil ?? .distantPast) > Date()
    }

    /// Touch ID 또는 로그인 암호로 인증한다. 인증 수단이 없으면 통과시킨다.
    func authenticate(_ reason: String) async -> Bool {
        let ctx = LAContext()
        var error: NSError?
        guard ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else { return true }
        return (try? await ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)) ?? false
    }

    func unlock() {
        Task {
            if await authenticate("View the IP event log") {
                unlockedUntil = Date().addingTimeInterval(60)
            }
        }
    }

    func lock() { unlockedUntil = nil }

    /// 보안상 민감한 동작 전에 호출한다. 이미 잠금 해제되었거나 인증이 꺼져 있으면 바로 통과한다.
    private func authorize(_ reason: String) async -> Bool {
        if isUnlocked { return true }
        return await authenticate(reason)
    }

    // MARK: 사용자 동작

    /// 사용자가 직접 바꾼 변경을 확인 처리한다.
    func acknowledge() {
        if currentIP != nil { status = .ok }
    }

    func registerCurrentAsRealIP() {
        guard let ip = currentIP else { return }
        Task {
            guard await authorize("Change the registered real IP") else { return }
            vault.update { $0.realIP = ip }
            realIP = ip
            record(kind: "realip", from: nil, to: ip, endpoint: nil, fromCountry: nil, toCountry: currentCountry, alert: nil)
        }
    }

    func clearRealIP() {
        Task {
            guard await authorize("Remove the registered real IP") else { return }
            vault.update { $0.realIP = nil }
            realIP = nil
        }
    }

    func setRequireAuth(_ enabled: Bool) {
        if enabled { settings.requireAuth = true; return }
        Task {
            if await authenticate("Turn off authentication for the event log") { settings.requireAuth = false }
        }
    }

    func setLaunchAtLogin(_ enabled: Bool) {
        do {
            if enabled { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
        } catch {}
        launchAtLogin = SMAppService.mainApp.status == .enabled
    }

    func clearLog() {
        Task {
            guard await authorize("Delete the event log") else { return }
            let alert = NSAlert()
            alert.messageText = "Delete the entire event log?"
            alert.informativeText = "This cannot be undone. The encryption key is also rotated."
            alert.alertStyle = .warning
            alert.addButton(withTitle: "Delete")
            alert.addButton(withTitle: "Cancel")
            NSApp.activate(ignoringOtherApps: true)
            guard alert.runModal() == .alertFirstButtonReturn else { return }
            store.clear()
            events = []
            integrityOK = true
            record(kind: "cleared", from: nil, to: nil, endpoint: nil, fromCountry: nil, toCountry: nil, alert: nil)
        }
    }

    func exportLog() {
        Task {
            guard await authorize("Export the event log") else { return }
            let panel = NSSavePanel()
            panel.nameFieldStringValue = "ip-events.csv"
            NSApp.activate(ignoringOtherApps: true)
            guard panel.runModal() == .OK, let url = panel.url else { return }
            let iso = ISO8601DateFormatter()
            var csv = "date,kind,from,from_country,to,to_country,endpoint\n"
            for e in store.loadAll() {
                csv += [iso.string(from: e.date), e.kind, e.from ?? "", e.fromCountry ?? "",
                        e.to ?? "", e.toCountry ?? "", e.endpoint ?? ""].joined(separator: ",") + "\n"
            }
            try? csv.write(to: url, atomically: true, encoding: .utf8)
        }
    }

    private func purgeExpired() {
        guard settings.retentionDays > 0 else { return }
        let cutoff = Date().addingTimeInterval(-Double(settings.retentionDays) * 86_400)
        if store.purge(olderThan: cutoff) {
            events = Array(store.loadAll().reversed().prefix(200))
        }
        integrityOK = store.integrityOK
    }
}
