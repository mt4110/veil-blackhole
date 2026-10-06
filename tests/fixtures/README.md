# オフラインの人工パケット

`query-v6-options.hex`はpadding-onlyのHop-by-HopとDestination Optionsを追加した人工IPv6入力。offsetと対応範囲は[拡張ヘッダー検証記録](../../docs/IPV6_EXTENSIONS.md)を参照。

全fixtureは人工的な固定バイト列です。実通信、Wireshark、BPFから採取したデータではありません。hexは空白と改行だけを許し、コメントやpcap headerを含みません。

## query-a.hex

72 bytesのタグなしEthernet / IPv4 / UDP / DNS queryです。

| frame offset | 長さ | 内容と期待値 |
| --- | --- | --- |
| 0 | 6 | 宛先MAC `02:00:00:00:00:53` |
| 6 | 6 | 送信元MAC `02:00:00:00:00:10` |
| 12 | 2 | EtherType `0x0800` |
| 14 | 20 | IPv4、IHL=5、total length=58、ID=0x1234、DF=1、TTL=64、UDP |
| 24 | 2 | IPv4 checksum `0x3c0c` |
| 26 | 4 | 送信元 `192.0.2.10` |
| 30 | 4 | 宛先 `198.51.100.53` |
| 34 | 8 | UDP、送信元53000、宛先53、length=38、checksum=0x101f |
| 42 | 12 | DNS ID=0x1234、flags=0x0100、question=1、他section=0 |
| 54 | 14 | QNAME `tracker.test.`、root label終端 |
| 68 | 2 | QTYPE=A=1 |
| 70 | 2 | QCLASS=IN=1 |

各数値はnetwork byte orderです。IPとUDP checksumは人工生成時に算出し、独立したtcpdumpのオフライン読み取りでもQNAME、type、address、port、UDP checksumを確認しました。アナライザ本体はchecksumを検証済みとは表示しません。

## その他のfixture

| ファイル | 内容 |
| --- | --- |
| query-options.hex | IHL=6、4 bytesのNOP options、IPv4 total length=62、checksum=0x3906。UDP/DNSは同じで、76 bytes |
| dns-query-a.hex | query-aのDNS payloadだけ、30 bytes |
| bpf-two-records.hex | classic Darwinの人工recordを2件並べた190 bytes |
| bad-udp-length.hex | query-aのUDP lengthだけを7へ変更した異常入力。期待結果はUDP length error |

人工BPF recordはlittle endianで、`tv_sec:i32=1`、`tv_usec:i32=2`、`caplen:u32=72`、`datalen:u32=72`、`hdrlen:u16=22`、4 bytesのheader padding、72-byte frameです。最初のrecordは94 bytesの後に2 bytesのalignment paddingを置き、次recordはoffset 96から始めます。最後はoffset 190でframeが終わり、末尾paddingを省いています。

このlayoutは確認したmacOS SDKのclassic `bpf_hdr` / `timeval32` / 4-byte alignmentに合わせています。extended header、別OS、別endian、live captureのABI対応は含みません。fixtureを更新する際は、変更箇所と期待値を同時に更新し、独立した解析でも確認してください。

## query-v6.hex

人工的な92-byteのEthernet / IPv6 / UDP / DNS query。EtherType 0x86dd、IPv6 version=6、payload length=38、Next Header=17、Hop Limit=64、source=2001:db8::10、destination=2001:db8::53。UDPは53000→53、length=38、checksum=0xa0bd。DNSの30-byte payloadはdns-query-a.hexと同じで、ID=0x1234、tracker.test. A IN。

IPv6 headerはoffset 14から40 byte、sourceはoffset 22から16 byte、destinationはoffset 38から16 byte、UDPはoffset 54、DNSはoffset 62。IPv6 pseudoheaderを含むchecksumを独立検算し、tcpdumpのオフライン解析でも確認した。実ネットワークから取得したframeではない。

## bad-udp-checksum.hex

query-a.hexのDNS ID（offset 42〜43）だけを7に変更し、UDP checksumを更新しない人工入力。構造のみの再生は成功するが、--verify-checksumsではUDP checksum error、malformed=1、終了コード2となる。送信用ではない。
