# IPv6対応の実装と検証

2026年10月6日 JST。既存DNS resolverがIPv6であり、IPv4限定の試験ではen0のDNSを確認できなかったため、承認を受けて対応範囲を追加した。

## 追加した範囲

- PacketQueryのaddressをIpAddrへ変更し、IPv4の解析を維持したままIPv6を追加。
- タグなしEthernet、IPv6基本header 40 byte、Next Headerが直接UDP（17）、UDP宛先53番、既存のDNS query構造検証。
- IPv6 version、payload length、capture length、UDP lengthの境界を検証。末尾Ethernet paddingはDNSに含めない。
- classic BPFにEtherType別の分岐を追加し、IPv6 sourceの128 bitを4 wordすべて照合する。取得開始時の自端末IPv4/IPv6を合計最大16 addressまで登録する。
- IPv6の最大非jumbo payloadを含めるためsnaplenを65589 byte（Ethernet 14 + IPv6基本header 40 + payload 65535）に変更。read bufferの上限1 MiB、queue 16件は維持。
- interface snapshotにIPv6を含める。任意表示のIPv6 endpointは角括弧付きSocketAddr形式にする。

[RFC 8200の基本headerとextension header](https://www.rfc-editor.org/rfc/rfc8200.html)を参照した。拡張header、Fragment header（atomic fragmentを含む）、jumbogram、TCP、VLANは対応しない。extension chainを固定offsetのUDPとして誤解釈せず、filterで拒否し、decoderでも対象外を返す。checksumはoutbound offloadを考慮して引き続きunverifiedと表示し、IPv6 checksumの有効性を証明しない。

## オフライン検証

Rust 37件、Python orchestration mock 4件が成功した。既存のIPv4回帰に加えて、IPv6の固定field、全truncated prefix、payload/UDP length、version、拡張header/fragment/別port、末尾padding、mutation corpus、128-bit source照合、IPv6-only/最大16-address filter、合成BPF recordのworkerデコード、CLIの既定非表示と任意endpoint表示を確認した。

macOS付属libpcapのpcap_offline_filterによる独立評価119ケースが成功した。IPv4/IPv6を合わせたfilterを使い、2種類のIPv6 source、各wordの不一致、短いprefix、別protocolなどを評価した。実interfaceやBPF deviceを使わない。

固定fixture `query-v6.hex`は人工的な92-byte Ethernet frameであり、実通信から採取していない。IPv6 source=2001:db8::10、destination=2001:db8::53、UDP 53000→53、length=38、checksum=0xa0bd、DNS ID=0x1234、tracker.test. A INである。IPv6 pseudoheaderによる検算とtcpdumpの人工pcap読み込みでUDP checksumを確認した。

fmt、clippy（warningsをerror扱い）、release buildが成功した。依存追加はない。取得・送信権限を広げる機能、応答合成、OSのDNS設定変更、公開・commitは行っていない。

## 実機試験のまとめ方

`scripts/live-smoke.py`を一般ユーザーの認証済みターミナルから起動する。stdioだけを引き継いだsudo子processでen0の10秒取得を開始し、mode=liveを確認後、en0経由の既存IPv6 resolverへexample.com Aを通常のdigで1回問い合わせる。TCP retry・再試行・起動banner・名前/IP表示を抑え、raw packetや結果ファイルを保存しない。外部public resolverを勝手に選ばない。

`--check`はresolver経路の確認だけでdevice openとquery送信を行わない。取得開始が失敗した場合もqueryを送らない。Python mock試験ではこの順序と、名前/IP非表示、解析不正がある場合の不合格を確認した。observed判定はquery countが非zeroでmalformed/truncatedが0の終了結果であり、送った1件と個別に同定した保証ではない。digの応答成否は別に表示する。

Codex側で--checkは成功した。実機試験scriptも起動したが、sudo認証が共有されず、BPF取得開始前に終了し、queryは送信されなかった。認証済みTerminalの自動操作もツールの安全制限で拒否されたため、他のUI操作手段へ迂回していない。今回のIPv6版での実read/decoder成功は、利用者のターミナルでのscript実行結果を待つ状態である。以前のIPv4版で確認した時間満了・Ctrl-C結果をIPv6版の実機結果へ置き換えない。

## 実機BPFレコード不具合の修正

利用者の実機scriptでmode=liveへ到達し、test_query_attempts=1、dig_exit=0を確認したが、アナライザーはBPF record構造不正で停止し、capture_exit=3、result=unconfirmedとなった。旧errorには具体的な失敗理由とheader長が含まれていないため、実際のheader値は確認できていない。

コード調査で、classic Darwin BPF wire headerの最小長をCのsizeof(struct bpf_hdr)=20と同一視した欠陥を確認した。Apple XNUの[bpf.h](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/bpf.h)はC末尾paddingのためSIZEOF_BPF_HDRを18と定義し、[bpf.c](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/bpf.c)はBPF_WORDALIGN(link_header + SIZEOF_BPF_HDR) - link_headerでbh_hdrlenを計算する。Ethernetのlink header 14 byteではbh_hdrlen=18となる。

18-byte wire headerと正常queryを持つ合成recordで、修正前にBPF header lengthエラーになることを再現した。records.rsの必須field範囲を18 byteへ訂正し、bh_hdrlenに従ったpayload開始位置と4-byte次record alignmentを維持した。header不足、caplen/datalen不一致、buffer超過等の検査は維持する。C側のsizeof=20 assertionはlayout確認なので残し、field末尾が18であるassertionを追加した。

18-byte header、複数record、18/20/22-byte padding差、空frame、18 byte未満の拒否を回帰試験に追加し、workerのIPv6合成recordも18-byte headerへ変更した。Rustの最終39テスト、fmt、clippy、release buildが成功。実機で同じ原因だったかと修正版のread・decode成功は再試験を待つ。

BPF構造不正時のerrorに固定の失敗理由、read byte数、最初のrecordのhdrlenだけを追加した。packet bytes、timestamp、MAC、IP、domainは出さない。最初のheader metadataが後続recordの失敗を直接示すものではないことに注意する。

## 修正後の実機試験成功

利用者が認証済みの同じターミナルで修正版のlive-smoke.pyを実行し、次の出力を共有した。Codexが独立に採取した結果ではなく、利用者提供の実行結果を証拠として記録する。

```text
preflight interface=en0 resolver_transport=IPv6 names=false endpoints=false
mode=live access=read-only direction=outbound checksum=unverified names=false endpoints=false
test_query_attempts=1 dig_exit=0
queries=13 unsupported=0 malformed=0 truncated=0 display_dropped=0 kernel_received=415 kernel_dropped=0 interrupted=false
capture_exit=0
result=observed（実DNSのread・デコードを確認。queryの個別同定はしていません）
```

この環境・条件で、降格後のFDによる実read、classic Darwin BPF recordの解析、DNS queryデコード、既定の名前/endpoint非表示、時間満了での正常終了を確認した。mode=liveへの到達は実装上の権限確認を通過したことを示すが、独立したcredential/group観測とは区別する。修正後の実機成功は18-byte header拒否修正と整合する。ただし正常時のbh_hdrlen値を出力していないため、実header長を18と実測したとは記録しない。

queries=13には自然発生した他のqueryも含まれ得る。試験queryは1回送信しdig_exit=0であったが、名前を表示・保存・照合していないため、その1件を個別に同定していない。全13件がIPv6であるとも判定しない。packet checksumは引き続きunverifiedであり、今回のBPF dropが0だったことを欠落ゼロの一般保証にしない。

この条件でのPhase 1の基本経路は成立した。この時点では修正版のCtrl-Cとinterface切断/変更は未実施だった。後続の試験結果を以下に追記する。強制停止、長時間・高負荷、他OS/別interface、IPv6 extension/fragmentの実機試験は未実施。後続の応答合成、遮断、Network Extension、公開・releaseは今回の承認範囲に含めない。

## mise経由の取得と修正版の停止試験

2026年10月6日 JST。以下は利用者提供のターミナル出力であり、独立採取した結果ではない。名前・endpoint表示は無効、checksumはunverifiedである。

| 試験 | 共有された結果 |
| --- | --- |
| `mise run live-smoke` | dig_exit=0、queries=9、kernel_received=556、interrupted=false、capture_exit=0、result=observed |
| en0で30秒の時間満了 | queries=15、kernel_received=1943、interrupted=false、exit=0 |
| en0で取得開始後にCtrl-C | queries=1、kernel_received=35、interrupted=true、exit=130 |
| en0の60秒取得中にLAN切断を試験 | mode=liveの後に「interfaceには1〜16個のIPアドレスが必要です」、exit=3 |

集計が共有された最初の3試験はunsupported、malformed、truncated、display_dropped、kernel_droppedがすべて0だった。LAN切断試験では集計は表示されていない。IPの実数、flags、切断から終了までの時間、FD解放の独立観測は記録していない。

時間満了とCtrl-Cの終了理由・終了コードは期待値と一致した。LAN切断試験では取得開始後のinterface再確認が失敗し、エラー終了した。アドレス数を表示していないので、0個になったとは断定しない。切断時の挙動を、Wi-Fiへの自動追従やあらゆる回線変化の検知保証として扱わない。

## 取得中のエラー表示の改善

interface再確認が失敗した場合、原因の前に「取得中に対象インターフェースの情報を再確認できないため停止しました」を加えた。起動時の入力条件エラーと区別し、元の原因も保持する。終了コード3、取得条件、約500 msの確認間隔は変えない。

人工sourceで再確認エラーを返すケースを既存の資源解放試験に追加し、文言とsource解放を確認する。この表示変更後の実機LAN切断試験は未実施で、上記の実機結果は表示変更前の版の証拠である。
