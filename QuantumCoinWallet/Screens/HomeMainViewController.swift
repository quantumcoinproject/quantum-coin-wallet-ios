//
// HomeMainViewController.swift
//
// Port of `HomeMainFragment.java` / `home_main_fragment.xml`. Token
// list with pagination + `VerticalScrollIndicatorView`-equivalent
// thumbs. Tap a row to open the block explorer.
//
// Android reference:
//   app/src/main/java/com/quantumcoinwallet/app/view/fragment/HomeMainFragment.java
//   app/src/main/res/layout/home_main_fragment.xml
//

import UIKit

public final class HomeMainViewController: UIViewController,
                                           HomeScreenViewTypeProviding,
                                           UITableViewDataSource,
                                           UITableViewDelegate {

    public var screenViewType: ScreenViewType { .mainHome }

    private let table = UITableView()
    private let scrollIndicator = VerticalScrollIndicatorView()
    private var items: [AccountTokenSummary] = []
    private var nextPage = 1
    private var loading = false
    private var currentAddress: String { resolveCurrentAddress() }

    public override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = UIColor(named: "colorBackground") ?? .systemBackground
        table.dataSource = self
        table.delegate = self
        table.translatesAutoresizingMaskIntoConstraints = false
        scrollIndicator.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(table)
        view.addSubview(scrollIndicator)
        NSLayoutConstraint.activate([
            table.topAnchor.constraint(equalTo: view.topAnchor),
            table.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            table.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            table.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -12),

            scrollIndicator.topAnchor.constraint(equalTo: table.topAnchor),
            scrollIndicator.bottomAnchor.constraint(equalTo: table.bottomAnchor),
            scrollIndicator.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            scrollIndicator.widthAnchor.constraint(equalToConstant: 6)
        ])
        scrollIndicator.attach(to: table)
        table.register(TokenCell.self, forCellReuseIdentifier: "token")

        // Re-fetch the token list whenever the active network is
        // switched from the top-right dropdown. Android achieves this
        // by restarting `HomeActivity`; iOS just clears local state
        // and triggers a fresh page-1 fetch against the new chain's
        // scan API.
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(handleNetworkConfigDidChange),
            name: .networkConfigDidChange,
            object: nil)

        loadNextPage()
    }

    deinit {
        NotificationCenter.default.removeObserver(self)
    }

    @objc private func handleNetworkConfigDidChange() {
        items = []
        nextPage = 1
        table.reloadData()
        loadNextPage()
    }

    /// Hide / show the token list. `HomeViewController` calls this
    /// from the automatic-balance-error path (hide on balance failure,
    /// show on the next successful fetch) so the home main screen
    /// presents a clean "balance: -" state instead of a stale token
    /// roster when the network is unreachable.
    public func setTableHidden(_ hidden: Bool) {
        table.isHidden = hidden
        scrollIndicator.isHidden = hidden
    }

    private func loadNextPage() {
        guard !loading else { return }
        let address = currentAddress
        guard !address.isEmpty else { return }
        loading = true
        Task { [nextPage] in
            defer { self.loading = false }
            do {
                let resp = try await AccountsApi.accountTokens(address: address, pageIndex: nextPage)
                await MainActor.run {
                    self.items.append(contentsOf: resp.result ?? [])
                    self.table.reloadData()
                    self.nextPage += 1
                }
            } catch {
                // Silent: Android `HomeMainFragment.refreshTokenList`
                // mirrors this -- a failed listing leaves cached
                // state alone. The home path's automatic-error UX is
                // driven by the balance fetch (HomeViewController),
                // which hides the token table on failure; manual
                // refresh surfaces a dialog. Pagination errors here
                // simply don't extend the list.
            }
        }
    }

    private func resolveCurrentAddress() -> String {
        let idx = PrefConnect.shared.readInt(
            PrefKeys.WALLET_CURRENT_ADDRESS_INDEX_KEY, default: 0)
        return KeyStore.shared.address(forIndex: idx) ?? ""
    }

    public func tableView(_ tv: UITableView, numberOfRowsInSection section: Int) -> Int { items.count }

    public func tableView(_ tv: UITableView, cellForRowAt ip: IndexPath) -> UITableViewCell {
        let cell = tv.dequeueReusableCell(withIdentifier: "token", for: ip) as! TokenCell
        cell.configure(items[ip.row])
        return cell
    }

    public func tableView(_ tv: UITableView, willDisplay cell: UITableViewCell, forRowAt ip: IndexPath) {
        if ip.row >= items.count - 5 { loadNextPage() }
    }

    public func tableView(_ tv: UITableView, didSelectRowAt ip: IndexPath) {
        tv.deselectRow(at: ip, animated: true)
        let addr = currentAddress
        let url = Constants.BLOCK_EXPLORER_URL
          + Constants.BLOCK_EXPLORER_ACCOUNT_TRANSACTION_URL
          .replacingOccurrences(of: "{address}", with: addr)
        if let u = URL(string: url) { UIApplication.shared.open(u) }
    }
}

// MARK: - Token cell

private final class TokenCell: UITableViewCell {

    private let nameLabel = UILabel()
    private let symbolLabel = UILabel()
    private let balanceLabel = UILabel()
    private let contractLabel = UILabel()

    override init(style: UITableViewCell.CellStyle, reuseIdentifier: String?) {
        super.init(style: .default, reuseIdentifier: reuseIdentifier)
        let row1 = UIStackView(arrangedSubviews: [nameLabel, symbolLabel])
        row1.axis = .horizontal; row1.spacing = 6
        let col = UIStackView(arrangedSubviews: [row1, contractLabel, balanceLabel])
        col.axis = .vertical; col.spacing = 2
        col.translatesAutoresizingMaskIntoConstraints = false
        contentView.addSubview(col)
        nameLabel.font = Typography.mediumLabel(14)
        symbolLabel.font = Typography.body(12)
        balanceLabel.font = Typography.boldTitle(14)
        contractLabel.font = Typography.mono(11)
        contractLabel.textColor = .secondaryLabel
        NSLayoutConstraint.activate([
            col.topAnchor.constraint(equalTo: contentView.topAnchor, constant: 8),
            col.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -8),
            col.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 12),
            col.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -12)
        ])
    }
    required init?(coder: NSCoder) { fatalError() }

    func configure(_ t: AccountTokenSummary) {
        nameLabel.text = t.name ?? ""
        symbolLabel.text = t.symbol ?? ""
        balanceLabel.text = t.balance ?? ""
        contractLabel.text = t.contractAddress ?? ""
    }
}

// MARK: - VerticalScrollIndicatorView

public final class VerticalScrollIndicatorView: UIView {

    private weak var target: UIScrollView?
    private var observer: NSKeyValueObservation?
    private let thumb = UIView()

    public override init(frame: CGRect) {
        super.init(frame: frame)
        backgroundColor = .clear
        thumb.backgroundColor = UIColor(named: "colorPrimary") ?? .systemBlue
        thumb.layer.cornerRadius = 3
        addSubview(thumb)
        isUserInteractionEnabled = false
    }
    required init?(coder: NSCoder) { fatalError() }

    public func attach(to scrollView: UIScrollView) {
        target = scrollView
        observer = scrollView.observe(\.contentOffset, options: [.new]) { [weak self] _, _ in
            self?.setNeedsLayout()
        }
    }

    public override func layoutSubviews() {
        super.layoutSubviews()
        guard let sv = target, sv.contentSize.height > 0 else {
            thumb.frame = .zero; return
        }
        let viewport = max(sv.bounds.height, 1)
        let content = max(sv.contentSize.height, viewport)
        let thumbH = max(20, bounds.height * (viewport / content))
        let progress = max(0, min(1, sv.contentOffset.y / max(1, content - viewport)))
        let thumbY = (bounds.height - thumbH) * progress
        thumb.frame = CGRect(x: 0, y: thumbY, width: bounds.width, height: thumbH)
    }
}
