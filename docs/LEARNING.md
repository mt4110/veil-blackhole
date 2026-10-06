# コマンドで遊ぶDNS解析

IPv6のpadding-only拡張ヘッダー列は`mise run learn:ipv6-options`で再生できます。[対応範囲](IPV6_EXTENSIONS.md)はオフライン限定で、Liveは直接UDPのみです。

目標は「バイト列のどの値が、解析結果を変えるか」を自分で説明できることです。まず人工fixtureで予想→実行→コード確認を繰り返します。各実験は5〜10分を目安にし、1つ説明できたらそこで区切れます。

## 準備

一般ユーザーのターミナルで実行します。

```sh
cd /Users/takemuramasaki/_workspace/veil-blackhole
mise trust
mise install
mise exec -- rustc --version
mise tasks
```

Rustの版は`rust-toolchain.toml`が唯一の設定元です。miseはプロジェクトのidiomatic-file設定でこれを読みます。Python 3、make、macOS SDK/C compilerはホスト環境を使います。miseだけでSDKを固定する構成ではありません。一般ユーザーで`mise run check`を実行し、準備を確認できます。

## 1. IPv4とIPv6を比べる

```sh
mise run learn:ipv4
mise run learn:ipv6
```

両方とも`queries=1`、名前は`tracker.test.`です。IPだけが変わる理由を、[fixtureのoffset表](../tests/fixtures/README.md)と`src/decode.rs`で追います。IPv4はIHLでheader長を計算し、IPv6は基本headerの40 bytesを使います。現在はIPv6拡張headerを扱いません。

名前・IPの表示は人工fixtureにだけ付けています。これらのコマンドはBPFを開かず、パケットを送信しません。

## 2. DNSだけを取り出す

```sh
mise run learn:dns
mise run learn:bpf
```

DNSだけの再生ではEthernet/IP/UDPを検証しません。BPFの人工入力は2レコードなので`queries=2`です。BPF header、取得frame、次recordまでのpaddingを、Ethernet headerと分けて考えます。`bh_hdrlen`と4-byte alignmentの扱いを`src/bpf.rs`で確認します。

## 3. 壊れた長さを拒否させる

```sh
mise exec -- cargo run --locked -- replay --fixture tests/fixtures/bad-udp-length.hex
echo "exit=$?"
```

期待値は`malformed=1`、終了コード2です。UDP headerは8 bytesなのに、入力のlengthが7になっています。エラーを成功扱いせず、境界を守れているか観察します。

```sh
mise exec -- cargo test --locked --test decode ipv4_and_udp_length_boundaries_are_checked -- --exact
mise exec -- cargo test --locked --test ipv6 extension_fragment_other_transport_and_other_port_are_explicitly_unsupported -- --exact
```

対応できない形式の`unsupported`と、不正入力の`malformed`を区別できたら、この実験は完了です。

## 4. 人工パケットを1か所だけ変える

次はDNS Transaction IDだけを変える実験です。元fixtureを変更せず、Git対象外の`.local/learn`へ新しいファイルを作ります。既存の同名ファイルがあれば上書きせず停止します。

```sh
mise exec -- python3 - <<'PY'
from pathlib import Path
frame = bytearray.fromhex(Path('tests/fixtures/query-a.hex').read_text())
frame[42:44] = (7).to_bytes(2, 'big')
out = Path('.local/learn/query-id-7.hex')
out.parent.mkdir(parents=True, exist_ok=True)
with out.open('x') as file:
    file.write(frame.hex(' ') + '\n')
PY
mise exec -- cargo run --locked -- replay --fixture .local/learn/query-id-7.hex --show-names
```

期待値は`id=7`、`queries=1`です。変更でUDP checksumが古くなりますが、本体はchecksum未検証のため解析します。これも学習ポイントです。この変更ファイルを送信したり、checksumが正しいfixtureとして扱ったりしません。値を変えて再実験する場合は出力名も変えてください。

## 5. filterとdecoderを区別する

```sh
mise run learn:filter
mise exec -- cargo run --locked --example filter_dump
```

macOS付属libpcapのオフライン評価器で人工入力を検証します。実通信は取得しません。filterは取得対象を絞る処理で、decoderは受け取ったバイト列の構造を検証する処理です。filterを通っただけでDNSが正しいとは保証できません。生成する人工検証ファイルは`.local/validation/native-filter`に置きます。

## 6. 自分の実通信を短時間だけ観察する

```sh
mise run live-preflight
sudo -v
mise run live-smoke
```

現在のhelperは`en0`と既存IPv6 resolverの経路を確認し、10秒取得中に標準の`dig`でテストDNS問い合わせを1回送ります。条件に合わない環境では停止します。scriptとビルドは一般ユーザーで実行し、helperが完成済みバイナリだけを`sudo -n`で起動します。名前・IPを表示せず、生パケットを保存しません。

`queries>0`は対象DNSを観測した証拠ですが、その1件のテスト問い合わせを個別同定した証拠ではありません。DoH/DoT、TCP、mDNS、VPN、キャッシュ済みの名前解決は対象外なので、ブラウザ操作で件数が増えるとは限りません。

Ctrl-C停止を試す場合は、認証済みターミナルで次を実行して停止します。

```sh
mise run build-release
sudo -n ./target/release/veil-blackhole capture --interface en0 --duration 30
echo "exit=$?"
```

期待値は`interrupted=true`と終了コード130です。時間満了なら`interrupted=false`と終了コード0です。新しい版での実機試験結果は、[IPv6検証記録](IPV6_VALIDATION.md)の確認範囲と分けて扱います。

## 7. チェックサムで変更を検出する

```sh
mise run learn:checksum
```

人工IPv4は`ipv4_header=valid udp=valid`、IPv6は`ipv4_header=not-applicable udp=valid`を表示します。実験4で作ったID変更ファイルに`--verify-checksums`を加えると、UDP checksumが古いためmalformed、終了コード2になります。オプションなしの再生結果と比較できます。

```sh
mise exec -- cargo run --locked -- replay --fixture .local/learn/query-id-7.hex --verify-checksums
echo "exit=$?"
```

この検証はオフライン限定です。Liveのchecksumは引き続きunverifiedです。
