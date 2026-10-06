# Changelog

## Unreleased

### Added

- rust-toolchain.tomlを読むmise設定と、開発・学習・CI相当のタスク。
- オフライン再生の任意チェックサム検証。IPv4 headerとIPv4/IPv6 UDPに対応。
- オフラインのpadding-only IPv6 Hop-by-Hop/Destination Options解析と上限検証。
- macOS上でオフライン検証だけを実行するGitHub Actions workflow。
- 人工fixtureと境界回帰試験、コマンドによる学習ガイド。

### Changed

- 取得中のinterface再確認エラーに、停止状況と元の原因を表示。
- 利用者提供のmise経由取得・時間満了・Ctrl-C・LAN切断の証拠を検証記録へ追記。
- README・CLI help・初期設計と現在の対応範囲の説明を整備。

Liveの取得範囲は直接UDPに限定し、checksumはunverifiedのまま。送信・遮断は追加していない。2026年10月6日のローカル最終検証はRust 49件、Python 4件、人工filter 119ケース、fmt、Clippy、release build、オフライン学習タスク、actionlintが成功。GitHub上のworkflow実行は未確認。
