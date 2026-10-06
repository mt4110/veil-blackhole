# Liveバックエンドの実装と検証

この文書の初回実装と実機結果はIPv4版の記録。後続のIPv6追加と現在の検証範囲は[IPV6_VALIDATION.md](IPV6_VALIDATION.md)を参照する。

2026年10月6日 JST。対象はLive実装のコード、ビルド、合成データによる境界試験である。初回の自動検証では実BPFのopen、root実行、実際の権限降格は実施していない。後続の利用者による実機試験結果を末尾に記録する。

## 実装

- `platform.rs`だけでunsafe Rust/OS APIを許可し、デコーダーを含む他のRust moduleではdenyする。
- `darwin.c`はSDKのifreq/BPF/audit構造とioctlを使う小さなABI境界。classic BPF headerのsize、offset、alignmentとfilter instruction sizeをcompile-time assertionで照合する。
- `/dev/bpf0`〜127をO_RDONLYで探索し、EBUSYだけ次へ進む。その他のopen失敗、FD属性不一致、通常ファイル、方向・DLT・filter設定失敗は終了する。
- 全拒否filterを先に設定する。限定filterはIHLに応じたUDP offset、送信元IPv4、UDP宛先53、fragment/reserved flagの除外を行う。DNS queryと構造は降格後のdecoderで確認する。
- `privilege.rs`は降格手順のfail-closed制御を定義する。Darwin APIはplatform境界に集約する。kernel audit UID、account primary GID/nameを確認し、rootの場合はinitgroups、setgid、setuidの順で降格し、実効/実UID/GIDを照合する。
- worker開始前は単一thread。既存threadまたはstdio以外の継承FDがあれば拒否する。FDを無条件に閉じるfallbackは設けない。
- workerがFDとbufferを所有し、mainへ最大16件のqueryをtry_sendする。表示が遅い場合は取得を待たせず、display_droppedを増やす。OS側のBPF dropは別統計で表示する。
- 100 ms以下のpoll、時間制限、interface情報の定期照合、停止signal、所有guardによるjoinとFD解放を実装する。

## 自動検証

Rustの試験は合計28件（decoder 14、CLI 4、Live境界5、模擬取得loop 5）。対象には次を含む。

- IHL/optionsと複数IPv4のclassic BPF filter、非対応protocol、fragment、他送信元、短いprefix、最大16-addressの分岐。
- 降格の各段階をmockで失敗させ、以降の段階と取得開始へ進まない制御。
- 模擬sourceでqueue満杯、名前非表示、BPF構造不正、送信元不一致、interface変化、read失敗、切詰めrecord、表示先切断、停止・期限を検証。
- 所有guardのjoinと模擬sourceの解放。これはOS上のFD解放・signal動作の実測ではない。

`scripts/check-native-filter.py`は生成した実filterを、macOS付属libpcapの`pcap_offline_filter`で評価する。固定fixture、options、2送信元、短いprefix、対象外packetの50ケースが成功した。interfaceやBPFデバイスを開かない独立したオフライン試験である。生成C sourceと実行binaryは`.local/validation/native-filter/`に置き、Gitから除外する。

`cargo test --locked`は28件すべて成功。`cargo fmt --all -- --check`、`cargo clippy --locked --all-targets -- -D warnings`、`cargo build --locked`と`cargo build --locked --release`も成功。release binaryで固定fixtureを再生し、問い合わせ名・endpoint・集計を確認した。

## ABIとAPIの根拠

対象SDKはXcodeに含まれるmacOS SDK。`net/bpf.h`のclassic headerはLP64でもtimeval32を使い、alignmentは4 byteである。Rust record decoderはcastせずlittle-endianの固定fieldを読む。Ethernet時の実bh_hdrlenとread結果は未実測である。

送信方向限定の[Apple XNU private header](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/bpf_private.h)にあるBIOCSDIRECTION/BIOCGDIRECTIONとBPF_D_OUTを限定的に定義した。[カーネル実装](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/bpf.c)のset/get処理を確認し、実行時にreadbackする。公開SDKに含まれず、将来互換性を保証しない。古いOSや対応しないkernelでは失敗させる。

監査identityにはSDK `bsm/audit.h`のgetaudit_addrを使う。[Appleのaudit構造](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/bsm/audit.h)とSDKを参照した。audit sessionが無効、root、account不明なら停止する。sudo -uでaudit identityと別accountを意図的に選ぶ利用、root daemon起動、setuid配布は対象外である。

ローカルの`man 2 setuid`は、rootのsetuid/setgidがreal/effective/saved IDを設定する契約を記載する。`man 3 initgroups`はDarwinのgroup cacheとdirectory serviceのmembershipを説明する。getgroupsの配列一致を権限全体の証明には用いない。呼出元ユーザーの権限への降格であり、sandboxではない。

依存にはロック済みの`libc 0.2.190`とbuild用`cc 1.6.0`を直接指定した。crates.ioで両方ともMSRV 1.65、MIT OR Apache-2.0、非yankedを確認。前回の90-package advisory照合に含まれるversionであり、今回versionを変更していない。アプリruntimeにはlibpcap、pnet、nix、Tokio、TUI、senderを追加していない。

## 残る実機検証

次は別途対象・時間・取得情報を承認した試験で、O_RDONLY openと限定ioctl、実readのclassic ABI、降格後のFD保持、実UID/GIDとgroup初期化、方向・自端末限定、Ctrl-C/時間切れ/切断時の停止を確認する。自動テストの成功を、この試験の成功と呼ばない。

poll/queueに上限を置いても、OSのaccount照会や標準出力の応答時間、schedulerの遅延を保証できない。workerの時間制限は取得loopの開始時点を基準とし、初期化や出力完了の全時間ではない。表示先が詰まるとmainの終了・集計が遅れる可能性がある。2回目の停止signalはこの場合の強制終了経路である。

interface変化検知は周期的照合であり、その間に変化・復帰した状態やIP spoofingを完全に検出しない。自己送信元の限定はprocess identityを証明しない。MAC/driver/kernelの無故障、安全な全通信の観測、欠落ゼロ、DLPとしての遮断を保証しない。

## 実機試験への着手記録

2026年10月6日 JST、利用者の承認を受けてdefault routeのinterfaceがen0であることを確認し、release buildを再確認した。ドメイン名・endpoint表示なしで10秒間の取得を予定し、`sudo -n ./target/release/veil-blackhole capture --interface en0 --duration 10`を試みた。

sudoがパスワード認証を要求して終了したため、アプリのLive入口、BPF open、降格、取得loopは実行されていない。これを取得失敗やBPFの互換性失敗とは判定しない。利用者本人のターミナルで認証して実行した結果が必要である。認証情報をチャットに提供する手順は用いない。

時間満了試験は10秒、停止試験は30秒の予定枠でCtrl-Cを1回押す。どちらも名前・endpointは表示せず、pcapや生packetを保存しない。自然発生のDNSが0件なら、実readと解析の成功は未確認として残す。試験のための外部DNS queryを自動生成しない。

## 利用者のターミナルで確認した実機結果

2026年10月6日 JST、利用者が同じ認証済みターミナルでrelease binaryを実行し、出力を共有した。Codex側で取得したログではなく、利用者から提供された実行結果を証拠として扱う。interfaceはen0、名前・endpoint表示は無効、生packet保存なし。

| 試験 | queries | kernel_received | kernel_dropped | interrupted | exit |
| --- | --- | --- | --- | --- | --- |
| 10秒の時間満了 | 0 | 1620 | 0 | false | 0 |
| 30秒枠でCtrl-Cを1回 | 0 | 439 | 0 | true | 130 |

両方ともunsupported、malformed、truncated、display_droppedは0。mode行は`access=read-only direction=outbound checksum=unverified names=false endpoints=false`であった。

確認できたのは、実機でLive初期化からworker起動へ到達し、時間満了およびCtrl-Cで正常に終了したことである。mode行へ到達する実装の制御フロー上、FD属性確認、送信方向の設定・読み戻し、initgroups/setgid/setuidと非root UID/GID照合を通過している。これは独立したOS credential観測やgroup membership全体の証明とは区別する。

queries=0のため、限定filterを通る実DNSのread、classic BPF recordの実デコード、DNS解析の成功はまだ確認できない。kernel_receivedはDNS query件数ではなく、非zeroでも実read成功の証拠とはしない。降格後のFDは保持されstatsを取得できたが、実packetをreadできた証拠は残っていない。取得方向・自端末以外を除外する実トラフィック試験、interface切断・変更、2回目のsignalによる強制終了も未確認。

## DNS問い合わせ試験の不成立と経路確認

利用者の追加試験ではqueries=0、kernel_received=1826、kernel_dropped=0、interrupted=true、exit=130。`dig -4 example.com A +notcp +ignore +tries=1 +time=2 +noall`はtimeoutを返した。取得と問い合わせの厳密な同時性は、共有出力だけでは判定できない。

設定を読み取り専用で調べたところ、/etc/resolv.confのnameserverはIPv6 literal 1件で、IPv4-mappedではなかった。その宛先へのIPv6 routeはen0。en0のDHCP optionからIPv4 DNS serverは得られなかった。resolverのIPや検索domainは記録・表示していない。scutilにもen0のresolverを確認した。

ローカルのman digは、-4/-6を指定したとき対応するtransportだけを試し、使用可能な宛先がなければlocalhostへ問い合わせる仕様を記載している。したがって、このIPv4限定の手順は現在の既存resolverを使うen0の試験条件を満たしていない。実際のdig packetは独立に取得していないため、個別の送信経路を実測済みとはしない。今回の結果だけでアナライザーのread/decoder不具合と判定しない。

既存resolverで試験を成立させるにはIPv6 UDP 53対応が必要になる。現行Phase 1のIPv4限定から実装範囲が広がるため、別途判断する。診断ではDNS設定変更・外部resolverへの切替・query再送・IPv6機能追加を行っていない。今後のdig手順では+nocmdも指定し、起動bannerを抑える。
