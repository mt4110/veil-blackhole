# Live試験の起動待ち：部分出力と期限

2026-10-14 JST。基準はmain `d5037b326beb9a29f3845ec8561ec1ada95f7cd7`。今回の対象は`live-smoke.py`の起動確認と回帰試験。実BPF取得、sudo、DNS送信、ネットワーク設定変更は実施していない。

## 再現した問題

可読通知の後でtext streamの`readline()`を呼んでいたため、子プロセスが`mode=live `だけを出力して改行しないと、次の期限チェックへ戻れなかった。ダミーのPython子プロセスは2秒で自然終了する有限のfixtureとし、試験用の起動期限だけを0.2秒へ短縮した。修正前は約2.03秒待機し、1.5秒の試験上限（起動期限＋後片付け余裕）を超えた。これは本番の20秒設定を実測した結果ではない。

正常起動行と集計行を同じwriteで出す対照でも、text streamが先読みした集計行を後続の`communicate()`で読み落とし、正常なダミー結果が`unconfirmed`になった。修正前の回帰試験では、部分出力期限と正常集計保持の2試験が失敗した。

## 修正

- 起動確認はunbufferedなbinary pipeからnonblockingの`os.read`で読み、改行までのbytesを保持する。selectorの待機にも期限までの残時間を使う。
- 完全な`mode=live `行の後に同じreadで届いたbytesを返し、後続出力と結合して集計する。
- 起動期限の既定20秒は維持。開始前の出力には64 KiB上限を追加し、未確認・EOF・上限超過では問い合わせへ進まない。
- selectorの終了とpipeのblocking属性復元を`finally`で行い、既存の`stop_capture()`による後片付けへ戻る。

Rustの取得処理、BPF、権限降格、既存resolver選択、queryの内容と回数、認証手順は変更していない。新規依存もない。

## 所有プロセスと外部操作の境界

追加試験は実際のPython子プロセスとpipeを使う。resolverはダミー値に置き換え、`dig`は実行せず呼び出し回数だけを記録する。既存のsudo kill経路も代替し、その引数のPIDが試験で起動した子と一致することを確認して、同じユーザーの子へ直接TERMを送る。未知の外部コマンドは試験失敗とする。

期限超過と出力上限ではTERMが1回呼ばれ、所有子がwait済みになったことを確認した。試験自身の失敗時も残った所有子だけを停止・waitする。実際のsudo monitorの停止権限・認証切れ・OS上のBPF FD解放は今回の証拠に含めない。

## 確認結果

Mac ARM64の固定Nix環境（Rust 1.98.1、Cargo 1.98.0、Python 3.14.7）、既存cacheを使用した。

| ケース | 結果 |
| --- | --- |
| 改行なし部分出力＋待機 | 起動失敗、query呼び出し0、期限の試験上限内、所有子を停止・wait |
| 分割された正常起動＋同じwriteの集計 | 模擬query呼び出し1、集計を保持、終了0・observed、子をwait |
| 改行前にEOF | 起動失敗、query呼び出し0、子をwait |
| 起動出力64 KiB超過 | 起動失敗、query呼び出し0、所有子を停止・wait |

既存4試験も維持し、全Python 8試験が成功。整形チェック、Clippy、Rust 58試験も成功した。Arenaの既存Blackhole一括入口でも正常19段階×2回が成功した。判定はダミーとオフラインの回帰結果であり、実DNS観測の新しい成功証拠ではない。

## 証拠と未検証事項

Gitignoredの`.local/validation/startup-pipe-20261014/`に`before.log`、`before-deadline.log`、`after.log`、`checks.log`を保存した。Arena側の`artifacts/startup-pipe-20261014/`に一括試験のログと各manifest／summary／Rust報告も保存した。

実Live、実sudo、実DNS送信は未検証。認証できず所有sudo processを止められない場合等、既存の後片付け経路の制約は維持される。起動期限は起動出力待ちの期限で、script全体や初期化前のresolver照会・後片付けの全時間ではない。以下も含め、本記録はPR提出前の結果。提出後のCI・マージ・公開状態はPRで別途確認する。

## Linuxでの追加検証

同日、Linux x86_64上の既存専用ビルダー`veil-arena-builder-1791624441124999000-daemon`で全Python 8試験が成功した。一般ユーザー（UID/GID 1000）で実行し、部分出力の期限切れ・所有子の停止とwait、分割正常起動と集計保持、EOF、出力上限を確認した。OS判定とresolverは代替し、sudo・digは実行せず、実際の子はPythonだけ。LinuxのLive対応やBPF取得の証拠ではない。

初回のNixシェル起動はコンテナ内のユーザー情報不足で停止し、試験は開始していなかった。依存取得・権限設定の変更はせず、既存Nix storeのPython 3.14.7を直接使って成功した。現行scriptと試験の2ファイルhashがLinuxの対象と一致した。今回Rustや依存は変更しておらず、LinuxでRust試験を再実行したとは扱わない。

Gitignoredの`.local/validation/startup-pipe-linux-20261014/`に、初回準備失敗の`linux-check.log`、成功した`linux-python-direct.log`、`linux-hashes.log`、`stop.log`を保持した。試験後は所有ビルダーを停止し、cacheと証拠を残した。Linux ARM64、実sudo monitorの停止、実DNS・BPFは今回未検証。
