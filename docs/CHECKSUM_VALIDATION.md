# オフラインチェックサム検証

2026年10月6日 JST。replayに任意の`--verify-checksums`を追加。既存の構造・DNS検証後、IPv4 headerとUDP疑似header/payloadを検証する。Liveの経路は変更しない。依存追加、実通信取得、送信はない。

IPv4 UDP値0は省略として受理し、IPv6の直接UDP値0は拒否。奇数byte末尾は計算上ゼロpadding。計算値ゼロを0xffffとして送る表現も検証する。Ethernet paddingとBPF headerはchecksum対象に含めない。

既存の独立検算済みIPv4・IPv4 options・IPv6 fixture、header/address/port/DNS ID変更、UDP checksum省略とゼロ拒否、奇数長、負のゼロ表現、全切詰めprefixを試験する。CLIではEthernet/BPFの検証結果、既定非表示、DNS単体・Liveへのオプション拒否を確認する。追加の人工入力は独立したu64合計・末尾foldの計算器で生成する。

検証に成功しても真正性や送信方向、実通信上の値は保証しない。この追加時点ではIPv6拡張header、jumbo、fragment等の対応範囲は拡張していない。後続のオフラインpadding-only拡張header対応は[別記録](IPV6_EXTENSIONS.md)を参照。

検証結果: Rust 45テスト、Python 4テスト、fmt、Clippy、release buildが成功。mise run learn:checksumで人工IPv4/IPv6のudp=valid表示を確認。checksum不正fixtureのCLI試験で終了コード2を確認。実通信取得・実機再試験は行っていない。
