# veil-blackhole

macOSで自身の平文DNS問い合わせを観測するための、Phase 1の研究実装です。人工パケットの再生CLIと、読み取り専用のLiveバックエンドを提供します。

[Phase 1の設計書](docs/PHASE1_DESIGN.md)では、BPFの読み取り専用open、取得対象、デコードの境界、権限、停止、表示とプライバシーを定義しています。送信・応答合成・遮断機能は実装対象に含めません。

Liveバックエンドは実装済みです。IPv4版では利用者の実機出力で初期化・権限確認の通過、時間満了、Ctrl-C停止を確認しました。IPv6追加とBPF header修正後の版でも、利用者の実機出力で実DNSのread・デコードと時間満了を確認しました。確認範囲と残る制約は検証記録を参照してください。送信、OSのDNS・経路変更、常駐、TUIは実装していません。rootでLiveを起動した場合は、初期化後に検証した非rootユーザーへ権限を降格します。

読み取り専用であることは無故障の保証ではありません。取得できないDNS経路、OSやドライバーの不具合、資源消費、表示される通信情報の扱いを設計・検証に含めます。

[DNSフィルタリング方式の比較案](docs/DESIGN.md)は、将来別途判断する参考資料です。Phase 1の実装指示や、Network Extensionへの移行承認として扱いません。

## ビルドとオフライン再生

検証した環境はApple silicon、macOS 27.0.1、Rust 1.98.1です。Rustの数値versionを`rust-toolchain.toml`、依存を`Cargo.lock`で固定しています。一般ユーザーで実行してください。

```sh
cargo build --locked
cargo run --locked -- replay --fixture tests/fixtures/query-a.hex
```

既定では名前とIPを表示せず、解析件数だけを表示します。人工fixtureの詳細を見る場合は、次のオプションを指定します。

```sh
cargo run --locked -- replay --fixture tests/fixtures/query-a.hex --show-names --show-endpoints
cargo run --locked -- replay --fixture tests/fixtures/dns-query-a.hex --format dns --show-names
cargo run --locked -- replay --fixture tests/fixtures/bpf-two-records.hex --format bpf-darwin
```

入力は最大1 MiBのASCII hexの通常ファイルです。pcap/pcapngの直接読み込みは提供しません。Ethernetと人工BPF形式はDLT_EN10MB、タグなしIPv4/IPv6（IPv6拡張ヘッダーなし）、非断片化UDP、宛先53番のqueryだけが対象です。DNSだけの形式ではL2/L3/L4の条件を検証しません。

出力の`checksum=unverified direction=unverified`は、checksum、送信方向、自端末由来をこの再生で確認していないことを表します。ファイルの内容が実通信を観測した証拠になるわけではありません。明示表示した名前やIPは標準出力に出るため、リダイレクト先やterminal記録にも残り得ます。

再生の終了コードは、0=完了（対象外packetを含む）、2=引数・読込み・解析不正または切詰めrecordです。`unsupported`、`malformed`、`truncated`を個別に集計します。

## Liveバックエンドの現在地

`capture --interface NAME --duration SECONDS`を実装しました。interfaceは必須、時間は1〜3600秒です。既定は件数のみで、名前・IPは`--show-names`と`--show-endpoints`で明示表示します。取得対象は、指定interfaceの自端末IPv4/IPv6送信元、タグなしEthernet、非断片化UDP、宛先53番のDNS queryです。IPv6拡張ヘッダー・断片化・jumbogram、TCP、VPN、DoH/DoT、mDNS、キャッシュ済みの名前解決は対象外です。

実通信を取得するため、オフラインの`replay`とは実行範囲が異なります。今回の実装作業ではLiveコマンドを実行していません。実機試験を行う場合は、対象interface、時間、表示・保存の扱いを先に決めてください。ビルドとテストは一般ユーザーで行い、管理者権限が必要な場合も完成済みバイナリだけを起動する手順です。`sudo cargo run`は使用しません。

実装上の境界は次のとおりです。

- BPFは`O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOFOLLOW`で開き、access modeを照合します。O_RDWRへのfallbackとプロミスキャス要求はありません。
- 最初に全拒否filterを設け、送信方向とDLTを確認してから、自端末IPv4/IPv6・UDP宛先53番の限定filterを設定します。
- rootの降格先はkernel audit sessionの非root UIDとaccount情報で確認します。環境変数だけで決めません。`initgroups → setgid → setuid → UID/GID確認`の失敗時は、parserとworkerを開始しません。
- stdio以外の継承FD、既にthreadを開始したprocess、無効なaccount、非対応interface/方向設定は拒否します。一般的な組込みlibraryとしての利用を意図していません。
- read bufferは最大1 MiB、表示queueは16件、poll待機は最大100 msです。kernelと表示queueの欠落を別々に集計します。
- interfaceのindex・IP・flagsを約500 msごとに再確認し、変化したら停止します。変化の瞬間を漏れなく検知する保証ではありません。
- Ctrl-C/SIGTERMで停止を要求し、workerをjoinしてFDを解放します。標準出力やOSサービスが止まって終了しない場合、2回目の停止signalはprocessを即時終了します。この経路では集計・Rust cleanupを保証しません。

Liveの終了コードは0=時間満了、3=初期化・取得・出力エラー、130=停止signalによる終了です。2回目のsignalによる強制終了は128+signal番号です。Live中の個別packetの解析不正・切詰めは集計して処理を継続し、BPFレコード構造不正は停止します。`kernel_received`はBPFの統計値で、DNS query件数とは一致しません。

送信方向のioctlは公開SDKにないApple XNUのprivate定義に依存します。設定・読み戻しの失敗時は停止し、取得範囲を広げません。実機ABI・権限・停止の検証範囲は[Live検証記録](docs/LIVE_VALIDATION.md)を参照してください。

## 検証

```sh
cargo test --locked
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
python3 scripts/check-native-filter.py
```

[fixtureの出所と期待値](tests/fixtures/README.md)、[オフライン検証記録](docs/VALIDATION.md)、[Live実装の検証記録](docs/LIVE_VALIDATION.md)を参照してください。macOSのビルドにはXcode Command Line Tools等のSDK/C compilerが必要です。独立filter試験はmacOS付属libpcapのオフライン評価器を使い、アプリ自体はlibpcapへリンクしません。オフライン試験の成功は、BPF・権限降格・実通信の動作確認とは別です。

## IPv6対応後の実機試験

既存resolverのIPv6経路に合わせて、IPv6基本header直後のUDP DNSに対応した。[IPv6検証記録](docs/IPV6_VALIDATION.md)に自動試験と未検証事項を記載する。

認証済みの同じターミナルで次を実行すると、取得開始→既存IPv6 resolverへのテストquery 1回→10秒の終了待ちをまとめて行う。script自体にはsudoを付けない。名前・IP・生packetの保存は行わない。

```sh
python3 scripts/live-smoke.py
```

認証が切れている場合は、先に同じターミナルで`sudo -v`を実行する。`python3 scripts/live-smoke.py --check`は経路確認だけで、取得とquery送信を行わない。resolver設定の変更や公開DNS serverへの切替は行わない。
