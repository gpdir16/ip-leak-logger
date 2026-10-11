import SwiftUI
import AppKit
import Combine

@main
struct IPLeakLoggerApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate

    var body: some Scene {
        // 창은 AppDelegate가 직접 관리한다.
        Settings { EmptyView() }
    }
}

@MainActor
final class WindowManager {
    static let shared = WindowManager()
    private var windows: [String: NSWindow] = [:]

    func show<Content: View>(_ id: String, title: String, @ViewBuilder content: () -> Content) {
        if let w = windows[id] {
            w.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            return
        }
        let controller = NSHostingController(rootView: content())
        let window = NSWindow(contentViewController: controller)
        window.title = title
        window.styleMask = [.titled, .closable, .miniaturizable]
        window.isReleasedWhenClosed = false
        window.center()
        windows[id] = window
        NotificationCenter.default.addObserver(forName: NSWindow.willCloseNotification, object: window,
                                               queue: .main) { [weak self] _ in
            Task { @MainActor in self?.windows[id] = nil }
        }
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, NSPopoverDelegate {
    private let monitor = Monitor.shared
    private var statusItem: NSStatusItem!
    private let popover = NSPopover()
    private var cancellables = Set<AnyCancellable>()

    func applicationDidFinishLaunching(_ notification: Notification) {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        statusItem.button?.target = self
        statusItem.button?.action = #selector(togglePopover)
        updateIcon()

        popover.behavior = .transient
        popover.delegate = self
        let host = NSHostingController(rootView: MenuView(
            monitor: monitor,
            onDetach: { [weak self] in self?.detach() },
            onSettings: { [weak self] in self?.openSettings() }))
        host.sizingOptions = [.preferredContentSize]
        popover.contentViewController = host

        monitor.$status
            .receive(on: DispatchQueue.main)
            .sink { [weak self] _ in self?.updateIcon() }
            .store(in: &cancellables)
    }

    private func updateIcon() {
        statusItem.button?.image = monitor.menuBarImage
    }

    @objc private func togglePopover() {
        guard let button = statusItem.button else { return }
        if popover.isShown {
            popover.performClose(nil)
        } else {
            popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
            NSApp.activate(ignoringOtherApps: true)
        }
    }

    /// 별도 창으로 분리해서 연다.
    private func detach() {
        popover.performClose(nil)
        WindowManager.shared.show("main", title: "IP Leak Logger") {
            MenuView(monitor: monitor, onDetach: nil, onSettings: { [weak self] in self?.openSettings() })
        }
    }

    private func openSettings() {
        popover.performClose(nil)
        WindowManager.shared.show("settings", title: "IP Leak Logger Settings") {
            SettingsView(monitor: monitor)
        }
    }

    // MARK: NSPopoverDelegate

    /// 팝오버를 끌어서 창으로 분리할 수 있게 한다.
    func popoverShouldDetach(_ popover: NSPopover) -> Bool { true }

    func popoverDidClose(_ notification: Notification) {
        monitor.lock()
    }
}
