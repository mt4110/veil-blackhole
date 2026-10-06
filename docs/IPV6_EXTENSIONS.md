# オフラインIPv6拡張ヘッダー

2026年10月6日 JST。replayのEthernet/BPF解析だけを拡張。Liveのfilterとデコーダーは直接UDPに限定したまま。

Hop-by-Hop（Next Header=0）とDestination Options（60）のpadding-only headerを辿る。Hdr Ext Lenは`(値 + 1) * 8`、Hop-by-Hopは基本header直後のみ。Pad1とゼロデータのPadNを受理し、TLV長とpayload境界を検証する。最大8 header・合計2048 bytesは処理資源の上限で、IPv6仕様の最大値ではない。Destination Optionsの重複は上限内で観測できるが、すべての推奨順序や意味を検証する実装ではない。

Routing、Fragment（atomicも含む）、AH、ESP、No Next Header、未知のtransport/option、jumbogramは対象外。RoutingやHome Address等のchecksum前提を変える情報を黙って飛ばさない。一般的なIPv6受信スタックの代替ではない。

checksumの疑似headerはUDPの長さ・protocol=17を使用し、拡張headerを合計に含めない。IPv6の基本payload長から拡張header分を除いたUDPを検証する。

根拠: [RFC 8200 §4](https://www.rfc-editor.org/rfc/rfc8200.html#section-4)、[§8.1](https://www.rfc-editor.org/rfc/rfc8200.html#section-8.1)。

人工fixture query-v6-options.hexは既存query-v6.hexにHop-by-Hop 8 bytesとDestination Options 8 bytesを加えた108 bytes。IPv6 payload length=54、UDP offset=70、DNS offset=78。アドレス・UDP・DNSは変更しないためUDP checksum=0xa0bdを維持する。実通信採取ではない。

正常chain、Pad1/PadN、全切詰めprefix、長さ超過、TLV不正、非ゼロPadN、途中Hop-by-Hop、Fragment等の拒否、上限8/9 header・2048/2056 bytes、mutation、checksum不一致、従来Liveデコーダーの拒否をテストする。Live filterの既存試験も維持する。

```sh
mise run learn:ipv6-options
```

実機拡張header取得、送信、Liveの取得範囲変更は行わない。

検証結果: Rust 49テスト、Python 4テスト、fmt・Clippy・release buildが成功。CLIの既定非表示・検証有効表示とmiseの学習コマンドを人工fixtureで確認。実通信取得・送信は未実施。
