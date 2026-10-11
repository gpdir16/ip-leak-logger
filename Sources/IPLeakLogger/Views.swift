import SwiftUI
import AppKit

private func kindStyle(_ kind: String) -> (symbol: String, color: Color, label: String) {
    switch kind {
    case "changed": return ("arrow.triangle.2.circlepath", .orange, "Changed")
    case "exposed": return ("exclamationmark.octagon.fill", .red, "Exposed")
    case "offline": return ("wifi.slash", .gray, "Offline")
    case "online": return ("wifi", .green, "Back online")
    case "realip": return ("lock.shield", .blue, "Real IP set")
    case "cleared": return ("trash", .secondary, "Log cleared")
    default: return ("play.circle", .secondary, "Started")
    }
}

// MARK: 메인(팝오버/분리 창 공용)

struct MenuView: View {
    @ObservedObject var monitor: Monitor
    var onDetach: (() -> Void)?
    var onSettings: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            header
            ipCard
            endpointList
            eventList
            footer
        }
        .padding(16)
        .frame(width: 360)
    }

    private var header: some View {
        HStack(spacing: 10) {
            Circle().fill(monitor.statusColor).frame(width: 12, height: 12)
                .shadow(color: monitor.statusColor.opacity(0.6), radius: 4)
            Text(monitor.statusTitle).font(.title3.weight(.semibold))
            Spacer()
            if monitor.status == .changed || monitor.status == .exposed {
                Button("Dismiss") { monitor.acknowledge() }
                    .buttonStyle(.borderedProminent).tint(monitor.statusColor).controlSize(.small)
            }
            if let onDetach {
                Button(action: onDetach) { Image(systemName: "macwindow.on.rectangle") }
                    .buttonStyle(.borderless).help("Open in a separate window")
            }
            Button(action: onSettings) { Image(systemName: "gearshape") }
                .buttonStyle(.borderless).help("Settings")
        }
    }

    private var ipCard: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("PUBLIC IP").font(.caption2.weight(.medium)).foregroundStyle(.secondary)
            HStack {
                Text(monitor.currentIP.map(monitor.display) ?? "—")
                    .font(.system(size: 26, weight: .semibold, design: .monospaced))
                    .textSelection(.enabled)
                Spacer()
                Button {
                    if let ip = monitor.currentIP {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(ip, forType: .string)
                    }
                } label: { Image(systemName: "doc.on.doc") }
                    .buttonStyle(.borderless).help("Copy IP")
                    .disabled(monitor.currentIP == nil)
            }
            HStack(spacing: 6) {
                Text(flagEmoji(monitor.currentCountry))
                Text(countryName(monitor.currentCountry)).font(.callout)
                Spacer()
                if let since = monitor.stableSince {
                    Text("stable for \(since, style: .relative)").font(.caption).foregroundStyle(.secondary)
                }
            }
            if let real = monitor.realIP {
                let isReal = monitor.currentIP == real
                Label(isReal ? "This is your real IP"
                             : (monitor.isUnlocked ? "Real IP: \(monitor.display(real))" : "Real IP registered"),
                      systemImage: isReal ? "exclamationmark.triangle.fill" : "lock.shield")
                    .font(.caption)
                    .foregroundStyle(isReal ? .red : .secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 10).fill(monitor.statusColor.opacity(0.12)))
    }

    private var endpointList: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("SOURCE").font(.caption2.weight(.medium)).foregroundStyle(.secondary)
            ForEach(monitor.endpoints) { e in
                HStack {
                    Text(e.host).font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary)
                    Spacer()
                    Text(e.latencyMs.map { "\($0) ms" } ?? "—")
                        .font(.caption).foregroundStyle(.secondary)
                    if let t = e.updated {
                        Text(t, style: .time).font(.caption2).foregroundStyle(.tertiary)
                    }
                }
            }
        }
    }

    private var eventList: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("EVENTS").font(.caption2.weight(.medium)).foregroundStyle(.secondary)
                Spacer()
                if !monitor.integrityOK {
                    Label("Log integrity broken", systemImage: "exclamationmark.shield")
                        .font(.caption2).foregroundStyle(.red)
                }
                if monitor.settings.requireAuth && monitor.isUnlocked {
                    Button { monitor.lock() } label: { Image(systemName: "lock.open") }
                        .buttonStyle(.borderless).help("Lock")
                }
            }
            if !monitor.isUnlocked {
                Button { monitor.unlock() } label: {
                    Label("Unlock to view events", systemImage: "touchid").frame(maxWidth: .infinity)
                }
                .controlSize(.large)
            } else if monitor.events.isEmpty {
                Text("No events yet").font(.caption).foregroundStyle(.tertiary)
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(monitor.events.prefix(60)) { e in eventRow(e) }
                    }
                }
                .frame(height: 150)
            }
        }
    }

    private func eventRow(_ e: LogEntry) -> some View {
        let s = kindStyle(e.kind)
        let ips = [e.from, e.to].compactMap { $0 }.map(monitor.display).joined(separator: " → ")
        return HStack(alignment: .top, spacing: 8) {
            Image(systemName: s.symbol).foregroundStyle(s.color).frame(width: 16)
            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 4) {
                    Text(s.label).font(.caption.weight(.medium))
                    if e.toCountry != nil { Text(flagEmoji(e.toCountry)).font(.caption) }
                }
                if !ips.isEmpty {
                    Text(ips).font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary)
                }
            }
            Spacer()
            Text(e.date, format: .dateTime.month().day().hour().minute().second())
                .font(.caption2).foregroundStyle(.tertiary)
        }
    }

    private var footer: some View {
        VStack(spacing: 8) {
            Divider()
            HStack {
                Button(role: .destructive) { monitor.clearLog() } label: {
                    Label("Delete log", systemImage: "trash")
                }
                .disabled(monitor.events.isEmpty)
                Spacer()
                Button("Quit") { NSApplication.shared.terminate(nil) }
            }
            .font(.caption)
        }
    }
}

// MARK: 설정

struct SettingsView: View {
    @ObservedObject var monitor: Monitor

    var body: some View {
        Form {
            Section("Detection") {
                Picker("Check interval", selection: $monitor.settings.intervalMs) {
                    Text("0.25 s").tag(250)
                    Text("0.5 s").tag(500)
                    Text("1 s").tag(1000)
                    Text("2 s").tag(2000)
                    Text("5 s").tag(5000)
                }
            }
            Section("Alerts") {
                Toggle("Show notifications", isOn: $monitor.settings.notify)
                Toggle("Play alert sound", isOn: $monitor.settings.sound)
                    .disabled(!monitor.settings.notify)
            }
            Section("Privacy & Security") {
                Toggle("Require authentication for events, export and deletion",
                       isOn: Binding(get: { monitor.settings.requireAuth },
                                     set: { monitor.setRequireAuth($0) }))
                Toggle("Mask IP addresses on screen", isOn: $monitor.settings.maskIP)
                Picker("Keep events for", selection: $monitor.settings.retentionDays) {
                    Text("Forever").tag(0)
                    Text("7 days").tag(7)
                    Text("30 days").tag(30)
                    Text("90 days").tag(90)
                }
                LabeledContent("Log integrity") {
                    Label(monitor.integrityOK ? "Verified" : "Tampering detected",
                          systemImage: monitor.integrityOK ? "checkmark.seal" : "exclamationmark.shield")
                        .foregroundStyle(monitor.integrityOK ? .green : .red)
                }
            }
            Section("Real IP") {
                LabeledContent("Registered") {
                    Text(monitor.realIP.map { monitor.isUnlocked ? monitor.display($0) : "••••••" } ?? "None")
                        .font(.system(.body, design: .monospaced))
                }
                HStack {
                    Button("Use current IP") { monitor.registerCurrentAsRealIP() }
                        .disabled(monitor.currentIP == nil)
                    Button("Remove") { monitor.clearRealIP() }
                        .disabled(monitor.realIP == nil)
                }
            }
            Section("Event log") {
                LabeledContent("Entries", value: "\(monitor.events.count)")
                HStack {
                    Button("Export CSV…") { monitor.exportLog() }
                    Button("Delete all…", role: .destructive) { monitor.clearLog() }
                }
                Text("Events are encrypted with AES-256-GCM. The key is kept in a single Keychain item.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("General") {
                Toggle("Launch at login", isOn: Binding(get: { monitor.launchAtLogin },
                                                        set: { monitor.setLaunchAtLogin($0) }))
            }
        }
        .formStyle(.grouped)
        .frame(width: 480, height: 620)
    }
}
