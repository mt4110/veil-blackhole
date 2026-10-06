# オフライン実装の検証（初回記録）

この文書は初回のオフライン実装時点の記録である。後続のLiveバックエンド実装と現在の検証範囲は[LIVE_VALIDATION.md](LIVE_VALIDATION.md)を参照する。

検証日：2026年10月6日 JST。対象：固定fixtureのデコードと再生CLI。OS設定変更、権限降格、BPF device access、live capture、query送信は実施していない。

## 環境と範囲

- macOS 27.0.1 build 26A434、arm64。
- Rust / Cargo 1.98.1、数値versionをtoolchainファイルで指定。
- `hickory-proto 0.26.3`、default feature無効、`std`のみ。MSRV 1.88、license MIT OR Apache-2.0、registryでyankedでないことを確認。
- IP/UDP/DNS fixtureは人工的な固定値。captured fixtureを使っていない。

DNSの構造検証には[Hickory](https://github.com/hickory-dns/hickory-dns)を使い、Ethernet/IPv4/UDP、人工BPF record、hex入力の境界検証はプロジェクト内で行う。crypto provider、DNSSEC validator、Tokio、TLS、datalink sender、直接のlibc/nix依存を追加していない。HickoryにはURL/IDNA等の推移依存があるため、ロックされた依存全体も点検対象とする。

## 実施結果

| 確認 | 結果と証拠の範囲 |
| --- | --- |
| `cargo check --locked` | 成功。アプリとDNS parserの型・APIの整合を確認 |
| `cargo test --locked` | decoder 14件、CLI 4件が成功。下記の異常系・境界を確認 |
| `cargo build --locked` | debug build成功。通常のframe再生と人工BPFの2-record再生を実行し、期待する集計を確認 |
| fmt / clippy | `cargo fmt --all -- --check`と`cargo clippy --locked --all-targets -- -D warnings`が成功 |
| 独立decoder | tcpdumpを`-r`で人工pcapに対して実行。実interfaceを開かず、fixtureのquery、IP/port、type、UDP checksumを確認 |
| 依存advisory | OSV querybatchでCargo.lock内のregistry package 90件を照合。照合時点の該当advisoryは0件。未知の脆弱性や全featureの安全性を保証する結果ではない |

主な境界試験は、短い全prefix、IHL/options、IP/UDPの長さ不一致、DF/MF/offset、VLAN/IPv6/TCP等の対象外、DNS query/response/opcode/class/count、trailing bytes、全sectionの圧縮名、pointer異常、binary labelとESCのescape、root/最大name長、EDNS/unknown RR、複数BPF record・alignment・切詰めである。

固定corpusの各byteを0、0xff、0xc0へ置換する決定的なmutation smoke testも実施する。これは長時間のcoverage-guided fuzzや、parserの無欠陥の証明ではない。

既定表示でQNAME/IPが出ないこと、明示表示では期待値が出ること、引数不正・異常fixtureの終了コード、liveコマンドが即座に`NotImplemented`で終了することをCLIの別processで確認する。

## 独立したfixture解析

人工Ethernet frameをpcap容器へ入れ、次のオフライン解析結果を得た。pcap容器は検証用に作ったものであり、captureしたファイルではない。

```text
link-type EN10MB (Ethernet)
IPv4: total length=58, ID=4660, DF, UDP
192.0.2.10.53000 > 198.51.100.53.53
[udp sum ok] 4660+ A? tracker.test. (30)
```

実施コマンドは`/usr/sbin/tcpdump -nn -vv -r .local/validation/synthetic-query.pcap`である。生ネットワークに対するtcpdumpは実行していない。固定hex、offset、期待値は[fixture資料](../tests/fixtures/README.md)に記載している。

## 依存の根拠

直接依存のversion・MSRV・license・featureはcrates.ioの[0.26.3 metadata](https://crates.io/api/v1/crates/hickory-proto/0.26.3)と取得したCargo.tomlで確認した。実APIは取得した当該版のsourceを確認している。

RustSecの[RUSTSEC-2026-0119](https://rustsec.org/advisories/RUSTSEC-2026-0119.html)は0.26.1以上で修正済み。[RUSTSEC-2026-0118](https://rustsec.org/advisories/RUSTSEC-2026-0118.html)と[RUSTSEC-2025-0006](https://rustsec.org/advisories/RUSTSEC-2025-0006.html)についても0.26.3は対象versionに含まれず、今回DNSSEC validationを有効にしていない。該当機能を将来有効にする場合は、別途確認する。

OSVの照合範囲は、現在のtargetで非activeなものも含むロック済みregistry依存である。結果は`.local/validation/dependency-advisories.json`へ保存した。version更新時には再照合する。

## 未検証と実装対象外

BPFのO_RDONLY open、kernel filter、方向限定、呼出元identity、Darwinの補助グループ、権限降格、capture workerの停止は未実装である。現在はunsafe codeをcrate lintで禁止し、live入口を失敗させている。`privilege.rs`は未検証の降格関数を置くためだけには作成していない。

人工BPF decoderはclassic Darwinのlittle endian・32-bit timeval・4-byte alignmentに限定する。対象SDKのheaderを参照したが、liveでのread結果との互換性を実測したものではない。非対応DLT・extended header・別OSのrecord形式は解釈しない。

IPv4/UDP checksum、送信方向、自端末由来は再生CLIでは検証しない。IPv6、TCP、VPN、DoH/DoT、mDNS、cached nameの観測にも対応していない。Linux/Intel/旧macOS、release build、長時間fuzz、runtime performance、Markdownの専用rendererは未検証である。
