# RPL module 設計制約と理由

本ドキュメントは、contrib/rpl 実装にあたって直面した ns-3 コアの制約と、
それに対する回避策・設計判断の理由をまとめたもの。ns-3 コア自体は変更しない方針のため、
制約の多くは model 層でのワークアラウンドとして解決している。

## 1. 動作モード

- **非 storing mode (MOP=1) のみサポート**。storing mode (MOP=2) は実装しない。
- 理由: 要件として非 storing mode を明示指定されたため。
- 影響: 下り経路情報 (Transit Information) は root のみが保持する。中間ノードは
  トポロジテーブルを持たず、送信元ルーティング (Source Routing Header, RFC 6554) で
  下り方向のパケットを転送する。

## 2. IPv6 拡張ヘッダーを送信元で挿入できない (解消済み: コアフック追加)

- **制約**: `Ipv6L3Protocol::Send()` は `RouteOutput()` 呼び出し前後でペイロード長を
  固定・切り詰める処理を行うため、送信元ノードで IPv6 拡張ヘッダー
  (Routing Header Type 3 など) をパケットに挿入することができない。
- **旧回避策 (廃止)**: 当初 `RplSourceRouteTag` を `Header` ではなく `Tag` として
  実装し、RFC 6554 RH3 のワイヤフォーマットをバイト列として PacketTag に
  格納する方式を採った。これは実際の拡張ヘッダーではなく帯域外メタデータであり、
  パケットは実際より 8 + 16n バイト軽い、という制約付きの実装だった。
- **現在の解決策 (ns-3 コア変更)**: 「正確に SRH で non-storing mode を実装」
  という要件のもと、ns-3 コアに最小限のフックを追加し、実際の RFC 6554
  拡張ヘッダーを送信元でパケットに挿入できるようにした。
  - `Ipv6RoutingProtocol::PrepareOutgoingPacket(packet, header, route)`
    (`ipv6-routing-protocol.h`) をデフォルト空実装の非純粋仮想関数として追加。
    `Ipv6L3Protocol::Send()` の 3 経路すべてで `SendRealOut()` 直前に呼び出し、
    呼び出し後に `header.SetPayloadLength(packet->GetSize())` で長さを再計算する
    (`ipv6-l3-protocol.cc`)。他のルーティングプロトコル (OLSR, AODV 等) は
    オーバーライドしないため影響なし。
  - `RplRoutingProtocol::PrepareOutgoingPacket()` が root 上でのみ、グローバル
    ユニキャスト宛かつ 2 ホップ以上の場合に `RplSourceRoutingHeader`
    (`Ipv6ExtensionRoutingHeader` のサブクラス) を `packet->AddHeader()` で
    実際に追加し、`header.SetNextHeader(IPV6_EXT_ROUTING)` と
    `header.SetDestination()` (最初のホップの link-local アドレスへ) を書き換える。
  - 受信側は `RplIpv6ExtensionSourceRouting` (`Ipv6ExtensionRouting` のサブクラス)
    を `Ipv6ExtensionRoutingDemux` に登録 (RPL 起動時、全ノード) することで対応。
    これは ns-3 core が RFC 2460 RH0 (`Ipv6ExtensionLooseRouting`) 用に既に
    持っている「宛先が自分自身になっているノードで拡張ヘッダーを処理し、
    宛先を次ホップへ書き換えて `RouteOutput()` 経由で再送出する」という
    汎用フレームワークへの新規登録であり、コア変更は不要 (`RplIpv6ExtensionSourceRouting`
    が private な `SendRealOut()` を呼べるよう、`Ipv6ExtensionLooseRouting`
    (RH0) に対する既存の `friend` 宣言と同じパターンで
    `friend class rpl::RplIpv6ExtensionSourceRouting;` を `ipv6-l3-protocol.h`
    に追加した点を除く)。
  - パケットは各ホップで実際に 8 + 16n バイト分の RH3 バイトを載せて運ばれる。
    アドレス圧縮 (CmprI/CmprE) は未実装のまま (常に非圧縮)。
- **参考にした先行事例**: TU Wien 2024 の Baranyai の RPL 実装 (thesis) は同種の
  制約 (ただし RPL hop-by-hop header 向け、RH3 向けではない) を Tag で回避して
  いた。本実装は最終的に Tag 方式を廃し、コアにフックを追加する方式へ移行した
  ため、この先行事例からは「技法」ではなく「制約の存在自体」の裏付けとしてのみ
  参照する。
- **別の先行事例 (問題自体を回避)**: Bartolozzi/Pecorella/Fantacci
  (Università di Firenze, Wns3 2012, "ns-3 RPL module: IPv6 Routing Protocol
  for Low power and Lossy Networks") は ns-3 本体への統合を目指した RPL 実装で、
  storing mode (MOP 3) のみをサポートすることで非 storing mode 特有の
  送信元ルーティング要件そのものを回避している (論文 3.3 節)。本実装は
  非 storing mode が要件のため、この回避策 (モード変更による問題消去) は
  採用できない。同モジュールは当時 802.15.4/6LoWPAN が未完成だったため
  point-to-point リンクでのみ検証されており、2026 年時点でも ns-3 本体には
  未マージ。
- **ICMPv6 ヘッダー設計の比較**: 上記 2012 年実装は各 RPL メッセージ型
  (DioHeader 等) を `Icmpv6Header` から直接継承する設計 (UML 上、論文 Figure 1)。
  本実装は継承せず、`Icmpv6Header` を type/code/checksum 用の別ヘッダーとして
  合成し (`SendRplMessageOn()`, rpl-routing-protocol.cc)、`RplDioHeader` 等は
  RPL メッセージ本体のみを担当する構成にしている。ns-3 core の `Icmpv6Echo` 等
  既存サブクラスを調べた結果、継承しても `Serialize()`/`Deserialize()` は
  基底クラス呼び出しをせず type/code/checksum を毎回re-implementしており、
  コード共有の実利は `CalculatePseudoHeaderChecksum()` 呼び出し程度。
  合成方式は同じ利益を得つつ RPL 本体ヘッダーを ICMPv6 に依存させない分、
  単体テストしやすい。継承への変更は不要と判断。

## 3. ICMPv6 type 155 (RPL) の受信

- **制約**: `Icmpv6L4Protocol` をサブクラス化して新しい ICMPv6 メッセージ型を
  追加するには ns-3 core の変更が必要。core 非変更の方針のため不可。
- **回避策**: `Ipv6RawSocketImpl` を使い、raw socket 経由で ICMPv6 パケットを
  受信し、`RecvRpl()` 内で type フィールドを手動チェックする。
- **付随制約**: `Ipv6RawSocketImpl` は public ヘッダーではないため、
  `DynamicCast<Ipv6RawSocketImpl>` や `Icmpv6FilterSetPass()` の呼び出しは
  コンパイル不可。フィルタ処理は行わず、type チェックのみで代替。
- **バインドの注意点**: raw socket は `ForwardUp()` 内でバインドアドレスと
  宛先アドレスの完全一致を要求する。リンクローカルアドレスにバインドすると
  マルチキャスト宛 (ff02::1a、全 RPL ノード宛) の DIS/DIO が破棄される。
  そのため `Ipv6Address::GetAny()` にバインドし、`BindToNetDevice()` で
  インターフェースを限定する。ソケット自身のアドレスをチェックサム計算に
  使えなくなるため、`GetLinkLocalAddress(interface)` ヘルパーを別途用意した。

## 4. IPv6 転送のシミュレーション特有の落とし穴

- **制約**: `Ipv6L3Protocol::IpForward()` は RFC 3849 ドキュメント用プレフィックス
  (2001:db8::/32) 宛パケットを転送しない。
- **回避策**: 実例 (`rpl-6lowpan-simple.cc`) のアドレッシングを `2001:1::/64` に
  変更。

- **制約**: `RouteOutput()` 内で「DODAG と同じ /64 プレフィックスを持つノードは
  オンリンク直接到達可能」と誤判定していた。実際には複数ホップ離れていても
  誤判定される。
- **回避策**: グローバルユニキャスト宛先に対するオンリンク判定を廃止。
  マルチキャスト・リンクローカル以外は常に DODAG 経由 (上り) または
  SRH 経由 (下り) でルーティングする。

## 5. 無線 PHY のシミュレーション特性への対処 (Freshness)

- **制約**: ns-3 の無線 PHY モデルは、感度限界付近で低確率ながら遠距離受信が
  成立することがある。実運用ではまず発生しないレアケースだが、シミュレーション上は
  ノードが遠距離ノードからの DIO をまれに 1 回受信し、それを親として
  ロックインしてしまうことがある。多ホップチェーン構成でこれが発生すると
  経路が壊れる (6 ノード構成で 0/5 到達、という事象で発覚)。
- **回避策**: Contiki-NG の link-stats を参考に freshness カウンタ
  (`RPL_FRESHNESS_MAX=16`, `RPL_FRESHNESS_TARGET=4`) を導入。
  一定回数以上安定して受信できたノードが 1 つでもあれば、freshness 不足の
  候補親を選択対象から除外する。現在の preferred parent が stale 化した場合は
  継承した rank も破棄する。

## 6. Timer / EventId の使い分け

- **制約**: `ns3::Timer::Schedule()` は、既に pending なイベントがある状態で
  呼ぶと `NS_FATAL_ERROR` で abort する。一方、生の `EventId` を再代入する方式は
  古いイベントを無警告でリークする (キャンセルされないまま残る)。
- **設計判断**: 全ての周期的送信イベント (`m_disTimer`, `m_daoEvent`,
  `m_daoRetryEvent`, Trickle timer 内部の 2 イベント) を `Timer` に統一。
  OLSR (`src/olsr`) が周期送信に一貫して `Timer` を使っている慣習に合わせた。
  `Schedule()` 前に必ず `Cancel()` を呼ぶことで、pending 中の再スケジュールを
  安全にしている。

## 7. マルチインターフェースノードでの制御メッセージ重複

- **制約**: 単一の `SendRplMessage()` が全インターフェースをループして
  送信していたため、ユニキャストメッセージ (DAO, DAO-ACK) を持つノードが
  複数インターフェースを持つ場合、同一メッセージが重複送信されていた。
- **回避策**: `SendRplMessageMulticast()` (DIS/DIO、全インターフェースへ送信) と
  `SendRplMessageUnicast()` (DAO/DAO-ACK、最初の 1 インターフェースのみ) に分離。

## 8. トポロジテーブルの掃除タイミング

- **設計判断**: root が保持する `TopologyEntry` の期限切れエントリの掃除
  (`PurgeTopology()`) は、専用タイマーではなく `RouteOutput()` の root 分岐、
  すなわち `ComputeSourceRoute()` を呼ぶ直前で行う。
- **理由**: AODV (`src/aodv/model/aodv-routing-protocol.cc`) の
  `RoutingProtocol::Forwarding()` が `RoutingTable::Purge()` をホットパス上で
  呼び出す遅延クリーンアップ方式を踏襲。root がトポロジを実際に使う瞬間にだけ
  最新化されていればよく、常時タイマーで掃除する必要はない。

## 9. テストトポロジ上の設計前提

- **制約**: テスト (`rpl-test-suite.cc`) で、中間ノードにホップごとに別々の
  `SimpleNetDevice`/`SimpleChannel` を割り当てる構成にすると、
  `GlobalAddressOf()` の「1 ノード = 1 インターフェース = 1 プレフィックス」
  という前提が崩れ、DAO が広告する parent アドレスと子ノード側の近傍探索が
  食い違い、`NS_ASSERT` で落ちる。
- **設計前提**: RPL は LLN (Low-power Lossy Network) を対象とし、ノードは
  通常単一のマルチホップ無線インターフェースのみを持つ。テストもこれに合わせ、
  単一の共有 `SimpleChannel` 上で `BlackList()` を使いホップ関係を表現する
  構成に変更した。

## 10. 未対応・既知の制限 (優先度順に未実装)

- **Medium (解消)**: SRH 転送の実シミュレーション上での動作は
  `rpl-6lowpan-simple` 例 (LR-WPAN + 6LoWPAN route-over、3ノード) で
  end-to-end 確認済み (ping 5/5)。加えて `RplSourceRoutingProcessTestCase`
  で `RplIpv6ExtensionSourceRouting::Process()` の境界値
  (segments-left 不整合、マルチキャスト混入、hop limit 枯渇、中継 hop での
  `stopProcessing`、到達済みパケットの pass-through) を直接検証。
  `RplNoPathDaoTestCase` で No-Path DAO によるトポロジエントリ削除、
  `RplDaoAckRetryTestCase` で DAO-ACK タイムアウト・リトライ・
  リトライ枯渇 (`SendRawRplMessage()` によるパケット手動生成、および
  root 上の監視用 raw socket による送信回数カウントで検証、private
  state には触れない) をそれぞれ追加。ただし No-Path DAO 自体を
  本実装から**送信**する経路はまだ無い (下記参照)。
- **Low (ドキュメント化のみ完了、未修正)**: DODAG version number
  (`HandleDio()`) と DAO path sequence (`HandleDao()`) は、いずれも
  RFC 6550 section 7.2 の lollipop 比較を実装せず、素の整数比較
  (version) または比較なしの無条件上書き (path sequence) になっている。
  コード側にコメントで明記済み。256 回のバージョン変更・親変更が
  必要になる程度の実害のため、修正は見送り。
- **Low (完了)**: Sphinx モデルドキュメント作成
  (`contrib/rpl/doc/rpl.rst`、`utils/create-module.py` の標準構成に
  準拠。本体 doc ビルドへの登録は行っていない — contrib モジュールで
  upstream 予定もないため)。
- **既知の非対応事項**: RFC 6553 (RPL Option, RPI) は 12 節の通り実装済み。
  RFC 6551/6719 (ETX/MRHOF) も 13 節の通り、RFC 6551 の LQL メトリックも
  14 節の通り実装済み (1 DIO への ETX/LQL 同時搭載も対応)。
  storing mode (MOP=2) は方針により対象外。RH3 アドレス圧縮
  (CmprI/CmprE) は 16 節の通り実装済み。6LoWPAN NHC 圧縮は Routing
  Header では効かない (11 節、RH3 自体の圧縮とは別の話)。RPI の
  確認済みループ (RFC 6550 section 11.2 の「2 回連続で不整合」) は
  実際にはパケットを止められない、既知の制約あり (12.2 節)。

## 11. ns-3 コアで見つかった既存バグ、および本実装側のバグ

正確な RH3 実装、および後述の RFC 6553 (RPI) 実装に切り替えた際、これまで
一度も実運用パスを通っていなかった ns-3 コアの IPv6 拡張ヘッダー/オプション
関連コードで、独立した既存バグを計 3 件発見・修正した (11.1〜11.3)。
このうち 2 件 (11.1, 11.2) は RPL 固有ではなく、RFC 2460 RH0
(`Ipv6ExtensionLooseRouting`) を 6LoWPAN 経由や、Hop-by-Hop header の後ろに
置いて使うだけでも再現する。11.4 は本実装 (contrib/rpl) 側の実装ミス。

### 11.1 SixLowPan の NHC 圧縮が Routing Header のアドレスを握り潰す

- **症状**: root がリーフに向けて SRH 付きパケットを送ると、中継ノードで
  `NS_ASSERT failed ... read beyond the bounds of the available buffer` で
  即クラッシュ。
- **原因**: `SixLowPanNetDevice::CompressLowPanNhc()`/`DecompressLowPanNhc()`
  (`src/sixlowpan/model/sixlowpan-net-device.cc`) が Routing Header を
  (de)serialize する際、`Ipv6ExtensionRoutingHeader` **基底クラス**の
  変数を直接使っていた。基底クラスの `GetSerializedSize()` は常に固定 4
  バイト (Next Header/Hdr Ext Len/Routing Type/Segments Left) を返す設計で、
  RH0 や RH3 が実際に持つ CmprI/CmprE/Pad/Reserved の 4 バイトとアドレス列
  (16n バイト) は一切考慮しない。したがって圧縮側はアドレス列を「次ヘッダー
  の中身」と誤認して破壊し、伸長側も同様に壊れたバイト列を組み立てる。
  `Ipv6ExtensionRoutingDemux::GetExtensionRoutingHeaderPtr(typeRouting)` という
  型ごとに正しいヘッダーオブジェクトを取得する API が用意されているにも
  かかわらず、この圧縮コードだけはそれを使っていなかった
  (`grep` で ns-3 全体を検索しても呼び出し元はここ以外に存在しない、
  いわば「作られたが繋がれなかった」API)。RH0 自体もこれまで 6LoWPAN
  経由で使われたことがなく (sixlowpan の既存テストにも Routing Header への
  言及は皆無)、埋もれていたバグと判断した。
- **修正方針の検討**: 正しい修正は圧縮・伸長の両方で
  `Ipv6ExtensionRoutingDemux` から型ごとのヘッダーオブジェクトを取得して
  使うことだが、共有コードの複雑な `Buffer` 操作を書き換えるのは
  この作業のスコープに対してリスクが大きいと判断した。代わりに
  `SixLowPanNetDevice::CanCompressLowPanNhc()` から `IPV6_EXT_ROUTING` を
  「圧縮可能」の一覧から外し、既存の未圧縮フォールバック経路
  (`iphcHeader.SetNh(false); iphcHeader.SetNextHeader(nextHeader);`、
  6LoWPAN が知らない Next Header に対して元々用意されている経路) に
  常に流すよう変更した。1 行の修正で安全、かつ「圧縮できる」という
  誤った申告を取り除くという意味で正しい。RH3 自体のアドレス圧縮を
  実装しない (10 節) という既存の判断とも整合する。
- **影響**: Routing Header を含むパケットは 6LoWPAN 上で非圧縮のまま
  送られる。フレームサイズは増えるが、正確性を優先。

### 11.2 中継ノードでの二重配送

- **症状**: 上記 11.1 を修正した後も、`std::out_of_range: vector` で
  クラッシュが継続。
- **原因**: `RplIpv6ExtensionSourceRouting::Process()` (RH0 の
  `Ipv6ExtensionLooseRouting::Process()` を範として実装) は、中継ノードで
  パケットを次ホップへ再送出したあと `isDropped = true` だけを立てて
  `stopProcessing` を立てていなかった。呼び出し元
  `Ipv6L3Protocol::LocalDeliver()` のループは `stopProcessing` しか見ておらず、
  `isDropped` だけでは「まだ処理を続けてよい」とみなして残りのバイト列を
  ICMPv6 層まで配送してしまう。結果として中継ノードは (a) 正しい再送出と
  (b) 自分宛でもない ICMPv6 ペイロードの誤配送、を二重に行っていた。
  この誤配送されたペイロードが Ping アプリケーション側の状態と噛み合わず
  `out_of_range` を誘発していた。**同じ問題は ns-3 本家の RH0 実装
  (`Ipv6ExtensionLooseRouting::Process()`) にも存在する**が、RH0 が
  6LoWPAN 経由は元より通常の IPv6 転送でも実運用テストされていないため
  顕在化していなかったと見られる。RH0 自体の修正は本実装のスコープ外
  として見送った。
- **修正**: 再送出後に `stopProcessing = true;` を明示的に設定
  (`rpl-source-routing-extension.cc`)。中継ノードが呼び出し元ループに
  「この受信処理は完了した、これ以上何もしなくてよい」と正しく伝える。

### 11.3 `Ipv6ExtensionRouting::Process()` が offset 未対応のまま `packet` を直読み

- **症状**: RPI (12 節) 追加後、Routing Header の直前に Hop-by-Hop header が
  付くようになった途端 (offset が 0 から 8 に変化)、中継先で
  `ICMPV6_UNKNOWN_OPTION` の Parameter Error が飛び、下り DAO-ACK やping応答が
  一切届かなくなった。
- **原因**: `Ipv6ExtensionRouting::Process()` (`src/internet/model/ipv6-extension.cc`)
  は `Ptr<Packet> p = packet->Copy(); p->RemoveAtStart(offset);` で offset 分
  読み飛ばした `p` を用意しておきながら、直後の
  `uint8_t buf[4]; packet->CopyData(buf, sizeof(buf));` で **`p` でなく
  `packet` を offset 0 から読んでいた**。`p` はこの関数内でこの1回しか
  使われず、完全な dead code だった。offset が常に 0 だった (Routing Header
  の前に何も無かった) これまでは症状が出ようがなく、埋もれていたバグ。
  Routing Type バイトを誤読した結果、無関係な値 (このケースでは RPI 自身の
  option type 0x63) を「未登録の Routing Type」と誤認し、
  `Ipv6ExtensionRoutingDemux::GetExtensionRouting()` が nullptr を返す経路に
  落ち、malformed 扱いで ICMP エラー送信・`stopProcessing=true` による
  即時ドロップに至っていた。
- **修正**: `packet->CopyData(buf, sizeof(buf));` を `p->CopyData(buf, sizeof(buf));`
  に変更。1 行の修正。

### 11.4 SRH 中継が Hop-by-Hop header を巻き込んで破棄していた (本実装側)

- **症状**: 11.3 を修正した後もダウンストリームの DAO-ACK/ping 応答が
  2 ホップ目から先に届かない。
- **原因**: `RplIpv6ExtensionSourceRouting::Process()` は中継用パケットを
  `p = packet->Copy(); p->RemoveAtStart(offset);` で組み立てる。RPI 追加前は
  Routing Header が常に packet の先頭 (offset=0) だったため、この
  「offset 分を読み飛ばす」操作は実質何も捨てていなかった。RPI 追加後は
  offset=8 (Hop-by-Hop header 分) になり、この操作が **HBH+RPI をそのまま
  捨てる** ことになっていた。次ホップへの再送出パケットに Hop-by-Hop
  header が存在しないにもかかわらず、IPv6 header の Next Header
  フィールドは (関数内でコピーしただけで書き換えていないため)
  "Hop-by-Hop" を指したままだったので、次ホップは Routing Header の
  先頭バイト列を Hop-by-Hop header として誤読した (11.3 の誤読とは別に、
  今度は正しい offset 計算でも中身自体が入れ替わっているため発生)。
  RFC 6553 は RPI がパス上の全ホップで検査・更新されることを前提とする
  ため、これは単なる見落としでは済まず、中継のたびに RPI が消える
  という実質的な仕様違反だった。
- **修正**: `Process()` の冒頭で
  `Ptr<Packet> prefix = packet->CreateFragment(0, offset);` により
  offset より前のバイト列 (HBH+RPI、この関数に来る前に RPI 自身の
  `Process()` で既に更新済み) を保存しておき、Routing Header の
  読み替え処理が終わった後で `prefix->AddAtEnd(p);` により結合、
  `RouteOutput()`/`SendRealOut()` には `p` でなく `prefix`
  (＝ [HBH+RPI][更新済み Routing Header][payload]) を渡すよう変更。
  offset=0 (RPI が無い場合) では `prefix` が空パケットになるだけなので、
  既存の動作に影響しない。

## 12. RFC 6553 (RPL Option, RPI) の実装

Hop-by-Hop header に載る RPI (data-path validation、rank 不整合＝ループの
早期検知) を実装した。SRH と違い、RPI は「パケットが今どのノード宛か」に
関わらず経路上の全ホップで検査・更新される必要があり、SRH (11 節) とは
別種の課題が出た。

### 12.1 コア変更は 1 行のみ

`ns3::Ipv6Option` (`src/internet/model/ipv6-option.h`) は RH0/RH3 のときの
`Ipv6ExtensionRouting`/`Ipv6ExtensionRoutingDemux` と同じ「サブクラス化して
demux に登録する」設計になっており、`Ipv6OptionDemux::Insert()` も public。
ただし `ipv6-option-demux.h` 自体が (`ipv6-extension-demux.h` と違って)
public header の一覧に入っておらず、contrib からは include できなかった。
`src/internet/CMakeLists.txt` の `HEADER_FILES` に1行追加して解消。
`friend` 宣言は不要だった (`Ipv6Option` に private メンバへのアクセスが
要る API は無い)。

### 12.2 Hop-by-Hop header の二重ディスパッチとその対処

`Ipv6L3Protocol::Receive()` は Hop-by-Hop header を、宛先判定より前に
自分で 1 回、その後、自分宛だった場合は `LocalDeliver()` の中でもう 1 回、
計 2 回処理する (`Ipv6ExtensionHopByHop::Process()` はどちらも `packet`
自体は書き換えず、ローカルコピー上でしかパースしないため、この二重呼び出し
自体は既存の Pad1/PadN/Jumbogram/RouterAlert のような無内容なオプションでは
無害だった、というのが埋もれていた理由と見ている)。RPI のように
SenderRank を実際に書き換える option だと、2 回目の呼び出しが「自分が
1 回目で書き換えた後の SenderRank」を見て再度整合性チェックしてしまう。

`PacketTag` で「処理済み」を示す案は、中継が必要な場合にこの node が
パケットを次ホップへ送り出すところまでで tag を消し切れる保証がなく
(その後の伝送で tag が生き残るかは NetDevice/Channel 実装依存)、
不採用。代わりに `Packet::GetUid()` を使った: `RplIpv6OptionRpl` が
node ごとに最後に処理した Uid を覚えておき、同じ Uid が来たら 2 回目と
みなして完全に素通りさせる。この state は「object ごと」(node ごとに
1 個だけ登録される) であり、パケット側には何も残さない。

ただし「他ノードや後続パケットとの衝突を考える必要が無い」というのは
誤りだった: `RplIpv6ExtensionSourceRouting::Process()` はホップごとに
`packet->CreateFragment()` でヘッダより後ろを切り出して書き換え、前段
(`CreateFragment(0, offset)` した `prefix`) に繋ぎ直す (11.4 参照) が、
`Packet::CreateFragment()` は既存の `PacketMetadata` をコピーして
範囲だけ絞る実装で、Uid はそこに含まれるため素通りする。つまり SRH で
中継されるパケットは、ホップを跨いでも **同じ Uid を持ち続ける**。
X → Y → X のように同じノードへ戻ってくるループがあれば、X は「前回
自分が処理したのと同じ Uid」を再び目にすることになり、上の重複排除が
これを「Receive()/LocalDeliver() の 2 回目呼び出し」と誤認して RPI
処理ごとスキップしてしまう —
RFC 6550 section 11.2 の rank 不整合検知 (まさにこの種のループを
見つけるための仕組み) を、その最も検知したいケースで自分から
無効化してしまっていた。

対策: Uid に加えて `Simulator::Now()` も一緒に記録し、両方が一致した
場合のみスキップする。同一パケットに対する `Receive()`/`LocalDeliver()`
の 2 回の呼び出しは必ず同一シミュレーションイベント内 (時刻が完全一致)
で起こるため、この判定はそのペアだけを捉え、時刻がずれて戻ってくる
ループパケットは (Uid が同じでも) 正しく再処理される。副次的に、初期値
`m_lastProcessedUid(0)` が `Packet::m_globalUid` の初期値 (0) と衝突し、
最初に送出されるパケットの Uid が常にこの番兵と一致してしまう問題も、
時刻の初期値に `Time::Min()` (シミュレーション中には現れない値) を
使うことで一緒に解消される。

### 12.3 「確認済み」の判定基準を取り違えていた、および確認済みループは実際には止められない

RFC 6550 section 11.2.2.2 の正確なルール (原文): 経路上で 1 回検知された
不整合は重大なエラーとはみなされずパケットは継続してよいが、同じパケット
について経路上で 2 回目の検知が起きた場合はそのパケットを MUST 破棄する。
これは「パケットに紐づく Rank-Error ビット」で制御される — 不整合を検知
したとき、そのビットがまだ立っていなければ立てて転送を続け、既に立って
いれば (=経路上のどこか別の場所で既に一度検知され、フラグ済みのまま
ここまで来た、ということ) 破棄し、Trickle タイマーを MUST リセットする。
判定基準は「このノードで何回検知したか」ではなく「そのパケット自身が
運んでいる Rank-Error ビットの値」であり、RFC 6550 section 11.2 の
「host/leaf は R ビットを必ず 0 で送出する」という規定が、すべてのパケット
がこのビット 0 から旅を始めることを保証している。

当初の実装はここを取り違えていた: 判定にパケット自身の Rank-Error ビット
(`RplPacketInfoHeader::GetRankError()`、既に定義されていたが一度も
呼ばれていなかった) を一切使わず、代わりに `RplIpv6OptionRpl` が
ノードごとに持つ状態 (`m_rankErrorSignaled`、「このノードで前回も
不整合を検知したか」) で代替していた。これは判定基準そのものが誤り
(「同じパケットが経路上で 2 回目」ではなく「このノードで 2 回連続」に
なっていた) であるだけでなく、副作用として Trickle リセットのタイミング
も RFC と逆転していた: 実装は 1 回目の検知で `NotifyRankInconsistency()`
を呼んでいたが、RFC が MUST としているのは「確認済み」(2 回目、ビット
既に立っている) の場合のみで、1 回目はビットを立てて何もせず転送する
だけでよい。

修正: `m_rankErrorSignaled` を削除し、受信した RPI の `GetRankError()`
を直接見る。ビットが立っていなければ (今回が経路上で最初の検知) ビット
を立てるだけで `NotifyRankInconsistency()` は呼ばない。ビットが既に
立っていれば (経路上で 2 回目、確認済み) `isDropped` をセットし、その
場合にだけ `NotifyRankInconsistency()` を呼ぶ。一貫性が確認できた
パケット (不整合なし) では、ビットが既に立っていてもそれをクリアしない
(RFC にクリアする規定は無く、経路のどこかで一度検知されたという事実は
保持したまま流れ続けるのが自然な読み)。

回帰テストとして `RplPacketInfoProcessTestCase` の「2 回連続」ケースを
書き直した: 旧テストは同じ `Process()` 呼び出しを立て続けに 2 回行って
「ノードの記憶」を頼りに確認済み判定を再現していたが、新しい実装では
これは単に「2 個の独立した、どちらも 1 回目の検知」になり
`isDropped=false` のまま (テストは実際にこの通りに失敗し、誤りの
存在を裏付けた)。正しい再現は、Rank-Error ビットを最初から立てた状態の
RPI (「既に別のホップで一度検知された」を模する) を新規に構築し、1 回の
`Process()` 呼び出しで確認済み判定になることを確認する形に変更した。

`Ipv6Extension::Process()` は `stopProcessing` という「これ以上何もするな」
を呼び出し元に伝える出力引数を持つが、`Ipv6Option::Process()`
(`virtual uint8_t Process(Ptr<Packet> packet, uint8_t offset, const
Ipv6Header& ipv6Header, bool& isDropped)`) には無い。`isDropped` はあるが
`Ipv6Extension::ProcessOptions()` はこれを一切 `stopProcessing` に変換
しないため、`isDropped=true` はトレース (drop trace 発火) のみで、実際には
パケットはそのまま配送・転送され続ける。`RplIpv6OptionRpl::Process()` は
確認済みループでも R フラグの付与とトレース、Trickle リセットまでは行うが、
上記の理由で実際にパケットを止めることはできない。対処として考えられる
のは (a) `Ipv6Option::Process()` へ `stopProcessing` 相当を追加するコア
変更、(b) この場でパケットの中身を壊して後続処理を意図的に失敗させる、
の 2 つだが、(a) は `Ipv6OptionDemux` に登録された全 option 実装への
破壊的変更になり影響範囲が読み切れず、(b) は 11.1 のバグと同種の
クラッシュを自ら誘発しかねない。ループが実際に確認される (経路上で
同じパケットが 2 回不整合を検知される) のはそもそも稀なケースである
ため、今回は見送った。RFC 6550 が意図する「早期復旧」の実利 (Trickle
リセットによる DIO 再送) は、確認済みと判定された時点で得られる。

### 12.4 送信側: Hop-by-Hop header の組み立て

`PrepareOutgoingPacket()` は、root かどうかで O フラグを決める
(root は常に down=true、それ以外は常に down=false — non-storing mode の
非 root ノードは自分から下り方向のトラフィックを発信することが無いため)。
`Ipv6ExtensionHopByHopHeader`(コア既存クラス) の `AddOption()` に
`RplPacketInfoHeader` を渡すだけで、8 バイト境界のパディング計算等は
既存コードに任せられる。SRH と両方付く場合は HBH が外側 (RFC 8200 の
推奨順序通り)。

### 12.5 root 発信の SRH: 応答がスコープ違反で握り潰されるバグ

- **症状**: root が非 root ノードへ ping 等の ICMPv6 リクエストを能動的に
  送る (今回のケースでは `SequentialPinger`、root から各ノードへ 1 台ずつ
  ping する検証シナリオ) と、2 ホップ以上先のノードでは Echo Request は
  正しく届くのに、その応答 (Echo Reply) が root に一切戻ってこない。1
  ホップ先 (root の直接の子) だけは機能する。
- **原因**: `ComputeSourceRoute()` が返す `hops` は、最終目的地自身を含めて
  全アドレスをリンクローカルで構築する (12 節冒頭のクラスコメント通り、
  「downward の経路は 1 radio hop ずつしか跨がないので全部リンクローカルで
  済む」という設計)。`PrepareOutgoingPacket()` がこれをそのまま
  `RplSourceRoutingHeader` のアドレス列にしていたため、SRH の最後の
  エントリ (= 最終目的地) もリンクローカルアドレスになり、
  `RplIpv6ExtensionSourceRouting::Process()` の `segmentsLeft` が 0 になった
  瞬間、IPv6 ヘッダの宛先はそのリンクローカルアドレスのまま最終ノードに
  届く。ns-3 コアの `Icmpv6L4Protocol::HandleEchoRequest()` は「受信した
  パケットの宛先アドレスをそのまま応答の送信元にする」実装のため、
  Echo Reply の送信元がリンクローカルアドレスになる。RFC 4291 のスコープ
  規則により、リンクローカル送信元のパケットは 1 hop しか運べず、
  `Ipv6L3Protocol::IpForward()` がこれを検知して黙って破棄する
  (中継ノードを 1 つでも経由すると即死) ため、2 ホップ以上先からの応答が
  一切戻らなかった。
- **これまで気付かなかった理由**: 既存の検証 (`rpl-6lowpan-simple.cc` 含む)
  は全て「leaf が root へ ping する」方向のみ。この場合 Echo Request は
  upward (SRH 不使用、preferred parent 経由) で、Echo Reply は root 発信の
  downward (SRH 使用) だが、その送信元は常に root 自身の正しいグローバル
  アドレスなので、このバグは踏まない。root が能動的に送信元になる
  ケースは今回初めてテストした。
- **試みて失敗した修正**: SRH の最終エントリだけを目的地のグローバル
  アドレスに差し替え、`RplIpv6ExtensionSourceRouting::Process()` が
  `RouteOutput()` の代わりに新設の public `RplRoutingProtocol::
  RouteToNeighbour()` を直接呼ぶようにして、`RouteOutput()` の
  「グローバル宛先は on-link とみなさない」制約 (13 節下、`RouteOutput()`
  自身のコメント) を SRH のコンテキストだけ迂回させる案を最初に実装した。
  3 ノードの既存テストは全て通ったが、10 ノードのランダムトポロジで
  別の重大な副作用が判明した: `RouteToNeighbour()` が返す `Ipv6Route` の
  Gateway にグローバルアドレスをそのまま入れると (`SetGateway(neighbour)`
  の `neighbour` がグローバルアドレスになるケース)、`Ipv6L3Protocol::
  SendRealOut()` -> `Ipv6Interface::Send()` に渡った際の近隣探索
  (Neighbour Discovery) やローカル配送判定がこの LLN 環境で正しく機能せず、
  DODAG のランクが際限なく増大していく不安定化を引き起こした
  (ping を一切送らない状態でも再現)。
- **最終的な修正**: SRH の最終エントリをグローバルアドレスにする変更は
  維持しつつ (`PrepareOutgoingPacket()`)、`RouteToNeighbour()` 自身に
  `neighbour.IsLinkLocal() ? neighbour : LinkLocalOf(neighbour)` を追加し、
  **Gateway (実際に無線で送る相手) は必ずリンクローカルアドレスに正規化**
  する形にした。これにより:
  - パケットの実際の次ホップ解決は、このモジュールの他の近隣探索と全く
    同じ「リンクローカルアドレス、1 radio hop」という前提のまま安定して
    動く (ランクの不安定化は解消)。
  - IPv6 ヘッダの宛先自体 (`Ipv6header.SetDestination(nextAddress)`) は
    グローバルアドレスのまま最終ノードまで届くので、そのノードが生成する
    応答の送信元もグローバルアドレスになり、上り方向の転送がスコープ規則
    に違反しなくなる。
  10 ノードのランダムトポロジで root からの ping が 9/9 (100%) 到達する
  ことと、`rpl-test` の全既存ケースが変わらず通ることを確認済み。
- **既知の残課題 (未修正、次回対応)**: このバグとは独立に、25 ノード以上の
  規模のランダムトポロジでは、ping を一切送らない状態でも DODAG のランク
  が時間とともに際限なく増大していく別の不安定化が観測された。OF0
  (RFC 6552) はヒステリシスを持たないため、輻輳した無線環境で一時的に
  親を見失うたびに `SelectPreferredParent()` が親を選び直し、それを
  繰り返すたびにランクが積み上がっていく (13.5 節の MRHOF ヒステリシス
  のような歯止めが OF0 には無い) ことが疑わしいが未検証。10 ノード規模
  までは再現しない。

## 13. RFC 6551 / RFC 6719 (ETX / MRHOF) の実装

これまで OF0 (RFC 6552、ホップ数のみ) しか実装しておらず、ETX は
`RplOcp` に列挙値があるだけの未実装プレースホルダーだった。ETX を実装し、
Wi-SUN FAN 1.1 の RPL プロファイルに合わせることを目的として、
MRHOF (RFC 6719) を OF0 と選択制で追加した。

### 13.1 Wi-SUN FAN 1.1 の RPL プロファイル調査

Wi-SUN Alliance の FAN 1.1 仕様書自体は会員限定配布であり、本文を直接
参照することはできなかった。公開されている二次情報 (IETF 6TiSCH/roll
関連ドラフト、Wi-SUN Alliance の公開資料・プレスリリース、他 OSS
実装のコメント) から確認できた範囲は以下の通り:

- ルーティングは non-storing mode (このモジュールの前提と一致)。
- Objective Function は MRHOF (RFC 6719)。
- ルーティングメトリックは ETX (RFC 6551 の Routing-MC-Type=7)。
- ETX は実機では Neighbor Discovery で得る双方向リンク品質
  (RSL: Received Signal Level) から導出する。
- 可能な限り 2 つ以上の親を維持することが望ましいとされる。

一方、Trickle の Imin/Imax、`PARENT_SWITCH_THRESHOLD` 等の
Wi-SUN 固有の数値チューニングは公開情報からは確認できなかった。
そのため本実装は **RFC 6719 自身が Section 5 で示すデフォルト値**
(`MAX_LINK_METRIC=512`、`MAX_PATH_COST=32768`、
`PARENT_SWITCH_THRESHOLD=192`) をそのまま採用している。Contiki-NG の
`rpl-mrhof.c` は同じ RFC を実装しながら異なるチューニング値
(`PARENT_SWITCH_THRESHOLD=96` など) を使っており、実装ごとに現場向けの
調整が入ることの傍証ではあるが、今回は「仕様に従う」という指示に対して
一次資料である RFC の値を優先した。13.7 節に既知の制限として明記する。

### 13.2 DAG Metric Container のワイヤフォーマット

`RplDioHeader` の DODAG Configuration option (既存) と同じパターンで、
DAG Metric Container option (RFC 6550 section 6.7.8、type=2) を追加した。
本実装が対応するのは ETX object (RFC 6551 section 4.3) のみで、
中身は次の 8 バイト固定:

```
type(2) length(6) MC-Type(7=ETX) Res+P+C+O+R(0) A+Prec(0) obj-length(2) ETX(u16, *128)
```

Aggregation (A) は additive (0) のみを送信・想定する
(RFC 6551 の ETX に対する既定値そのもの)。`Res+P+C+O+R`・`Prec` は
本実装では送信時 0 固定、受信時は無視 (未検査) している — 送るのは
自分自身なので、他実装が送ってくる非 0 値の解釈は不要という判断。

固定小数点スケールは ETX*128 (`RPL_ETX_FIXED_POINT`)。DIO のランクや
`MinHopRankIncrease` と同じ整数 (u16) の上で、ETX object のワイヤ表現
(RFC 6551 section 4.3 が定める `ETX * 128` の丸め整数) をそのまま
パス費用・リンク費用の内部表現としても使い回している。

なお RFC 6551 の common header (Routing-MC-Type の後に続く 2 バイトの
フラグ/aggregation/precedence フィールド) のビット位置は、WebFetch
経由での RFC 参照時に複数回にわたり内部矛盾する読み取り結果 (32 bit の
はずが合計 31 bit にしかならない等) を返された。今回必要な値は
全フィールドとも 0 なので、正確なビット位置に関わらずワイヤ上のバイト値
(0x00, 0x00) は不変というのを根拠に、この曖昧さを実害なしとして進めた。
ビット位置そのものへの依存 (0 以外の値を送受信する実装) が将来必要に
なった場合は、RFC 6551 の本文を (WebFetch ではなく) 一次資料から
直接確認すること。

### 13.3 リンク ETX の取得: lr-wpan への非依存

Wi-SUN FAN が実機で使う RSL 相当のものとして、lr-wpan の PHY が受信
フレームごとに付与する `ns3::lrwpan::LrWpanLqiTag`
(`src/lr-wpan/model/lr-wpan-lqi-tag.h`、「0-255 に正規化したパケット
成功率」) を採用した。ETX の瞬時値は `255 / LQI` で近似する
(LQI=0 の場合のみ `RPL_MRHOF_MAX_LINK_METRIC` に張り付ける)。

`librpl` は `libinternet` と `libsixlowpan` のみをリンクしており、
`liblr-wpan` への直接依存は無い。これは意図的な選択で、根拠は
`sixlowpan` モジュール自身が (802.15.4 上でしか実質使われないにも
関わらず) `liblr-wpan` を本体ライブラリではリンクせず、example だけが
リンクしているという既存の前例。この前例に倣い、`librpl` も新規に
`liblr-wpan` へ依存させることはせず、タグの中身は
`Packet::GetPacketTagIterator()` と、実行時に名前で解決した
`TypeId::LookupByNameFailSafe("ns3::lrwpan::LrWpanLqiTag", ...)`
経由で読む (`RplRoutingProtocol::LinkEtxFromPacket()`、
匿名名前空間の `LrWpanLqiPeekTag` がデコード用の器)。
`PacketTagIterator::Item::GetTag()` は渡した `Tag` の
`GetInstanceTypeId()` が一致するかしか見ないため、実際の
`LrWpanLqiTag` と同じワイヤフォーマット (1 バイト) を持つ器を
自前で用意し、`GetInstanceTypeId()` だけ実行時に解決した本物の
TypeId を返す、という方法でヘッダの `#include` もリンクも回避できる。

lr-wpan がリンクされていない実行体 (例: このモジュール自身のテスト
バイナリ `rpl-test`) では `LookupByNameFailSafe()` が false を返し、
`LinkEtxFromPacket()` は中立値 `RPL_ETX_FIXED_POINT` (ETX 1.0) に
フォールバックする。これにより既存の `SimpleNetDevice` ベースの
テスト群は一切影響を受けない — 全リンクが常に ETX 1.0 なので、MRHOF
選択時でも実質ホップ数と同じ挙動になる。

### 13.4 EWMA によるリンク ETX の平滑化

`Parent::etx` は DIO を受信するたびに `UpdateLinkEtx()`
(`rpl-routing-protocol.cc`) で更新する。初回サンプルは中立値からの
ブレンドではなく直接採用し (中立値からの EWMA だと新規リンクが
数 DIO の間「完璧なリンク」に見えてしまい本末転倒なため)、2 回目以降は
alpha=1/8 の EWMA (`etx - (etx >> 3) + (sample >> 3)`) を使う。
TCP の RTO 推定と同じ平滑度で、1 回のノイズに反応しすぎず、かつ実際の
変化には追従する、という一般的なトレードオフをそのまま踏襲した。
Wi-SUN FAN 1.1 固有の平滑化係数は 13.1 節の通り確認できていない。

### 13.5 MRHOF のランクとパス費用、ヒステリシス

`RankViaParent()`・新設の `PathCostViaParent()`
(`rpl-routing-protocol.h/.cc`) が RFC 6719 section 3.3 の式をそのまま
実装する:

- パス費用 = 親の advertise するパス ETX (`parent.pathEtx`、親の DIO の
  DAG Metric Container から) + そのリンクの ETX (`parent.etx`)。
  RFC 6551 の additive aggregation そのもの。
- ランク = `max(親のランク + MinHopRankIncrease, パス費用)`。
  パス費用がどれだけ小さくても、実際に辿ったホップ数分の
  `MinHopRankIncrease` を下回るランクを名乗ることはできない
  (RFC 6552 のループ防止不変条件を壊さないため)。

`SelectPreferredParent()` は OF0 と共通のコード (staleness pruning、
freshness によるブートストラップ猶予) はそのまま流用しつつ、
`m_ocp == RPL_OCP_MRHOF` の場合のみ:

- リンク ETX が `RPL_MRHOF_MAX_LINK_METRIC` 以上の候補、パス費用が
  `RPL_MRHOF_MAX_PATH_COST` 以上の候補は最初から除外 (RFC 6719
  section 3.2)。
- 残った候補の中でパス費用最小のものを "best" とする。
- 現在の preferred parent が生存していて、そのパス費用が
  `best のパス費用 + PARENT_SWITCH_THRESHOLD` 以下であれば、
  実際にはそちらを採用せず現在の親を維持する (ヒステリシス、
  RFC 6719 section 3.3)。

この結果、この node 自身が次の DIO で advertise するパス ETX
(`m_pathEtx`) も併せて更新する。root は常にパス ETX 0
(`SendDio()` 内、`m_isRoot ? 0 : m_pathEtx`)。

OF0 は従来通りコンパイル時のデフォルト (`m_ocp` の初期値は
`RPL_OCP_OF0`) のまま変更していない。既存テスト
(`RplDodagFormationTestCase` など) が OF0 のホップ数だけのランク式を
そのまま検証しており、これを壊さないことを優先した。MRHOF は新設の
`Ocp` attribute (root にのみ設定する — 他ノードは DIO の DODAG
Configuration option から追従する、既存の `m_ocp` 伝搬の仕組みそのまま)
で明示的に選択するオプトイン機能という位置付け。

### 13.6 実機相当での検証: LrWpanLqiTag は 6LoWPAN 経由でも生き残るか

これまで未検証だった懸念 — `LrWpanLqiTag` が
`SixLowPanNetDevice` の圧縮解除 (`DecompressLowPanIphc()` 等) を経て
`RplRoutingProtocol::RecvRpl()` まで実際に届くか — を
`rpl-6lowpan-simple --mrhof --verbose --distance=100` の実行で確認した。
既定の 60 m 間隔では `LrWpanErrorModel` を付けても LQI が飽和 (ETX
1.0 のまま) してしまい判別できなかったため、距離を 100 m まで離して
損失のある区間を作った結果:

```
Received a DIO from fe80::ff:fe00:1 ... (link ETX 1.04688): ... pathETX 0
Received a DIO from fe80::ff:fe00:2 ... (link ETX 1.04688): ... pathETX 1.04688
```

のように、リンク ETX が中立値 (1.0) から外れた実測値になり、かつ
2 ホップ目のパス ETX (2.09375) が 1 ホップ目のリンク ETX
(1.04688) のちょうど 2 倍になっている (RFC 6551 の additive
aggregation が正しく効いている) ことを確認した。これは同時に:

- `LrWpanLqiTag` が PHY 受信 -> MAC -> `LrWpanNetDevice` ->
  `SixLowPanNetDevice` の圧縮解除 -> `Ipv6L3Protocol` -> raw socket ->
  `RplRoutingProtocol` という経路全体を生き残ること、
- 13.3 節の TypeId 名前解決によるタグ読み取りが、実際に `lr-wpan` を
  リンクした実行体で正しく機能すること、

の両方を実証している。ping は 5/5 で成功しており、MRHOF 選択時でも
end-to-end の到達性に影響は無い。ただし直線トポロジのため、実際に
複数の親候補から異なるパス費用で選択する分岐そのものは、この example
では再現していない (それは 13.7 節の
`RplMrhofSelectionTestCase` で単体検証している)。

### 13.7 テストと既知の制限

`RplDioHeaderTestCase` に DAG Metric Container のシリアライズ/
デシリアライズ往復を追加。新設の `RplMrhofSelectionTestCase`
(`test/rpl-test-suite.cc`) は、実運用の DIO ではなく
`SendRawRplMessage()` で手作りした DIO を 2 系統の擬似隣接ノードから
注入し、パス費用に基づく選択とヒステリシスの両方を厳密な数値で検証する
(実際に踏んだ計算過程は同ファイルのコメントを参照)。`rpl-test` は
`liblr-wpan` をリンクしないため、この単体テストではリンク ETX は
常に中立値になる — 差分はすべて注入した DIO のパス ETX
(`SetMetricContainer()`) から来るように意図的に設計している。実リンク
品質からの ETX 導出そのものは 13.6 節の example 実行でのみ検証できる。

既知の制限:

- Wi-SUN FAN 1.1 固有の数値チューニング (Trickle 間隔、
  `PARENT_SWITCH_THRESHOLD` 等) は非公開のため未反映。RFC 6719 自身の
  デフォルト値をそのまま使っている (13.1 節)。
- `PARENT_SET_SIZE` (RFC 6719 の推奨値 3) による候補親数の上限は
  未実装。OF0 も同様に無制限に候補を保持しており、既存の挙動を踏襲。
- DODAG version number の lollipop 比較が未実装という既存の制限
  (10 節) は MRHOF 下でも変わらず残る。

### 13.8 コードレビューで見つかった問題の修正

実装後の自己レビューで、13.5 節のヒステリシス処理と、
`RplDioHeader::Deserialize()` の DAG Metric Container 解析に、
それぞれ実害のあるバグが見つかった。続けて行った、より広い範囲の
セルフレビューでさらに数件見つかり、あわせて修正した (下記)。

**ヒステリシスが loop-avoidance / freshness フィルタを再適用しない**

`SelectPreferredParent()` のヒステリシスブロックは、`best` を選ぶ
メインループを通過した候補にのみ課している loop-avoidance チェック
(`parent.rank >= currentRank` の候補を除外) と freshness チェックを、
現在の preferred parent に対しては再適用せず `m_parents.find()` で
直接引いていた。そのため、現在の親のランクが悪化してメインループでは
除外されるようになっても、パス費用さえ `best` に近ければヒステリシスが
無条件にその親を復活させてしまい、RFC 6552 のループ防止不変条件を
ヒステリシスの側から迂回できてしまっていた。メインループと同じ 3 条件
(freshness、loop-avoidance rank、`RankViaParent()` が
`RPL_INFINITE_RANK` でないこと) をヒステリシスブロックにも追加して
修正した。

**`i.Next(objLength)` がバッファ境界を越えて読み進める**

未知の Routing Metric/Constraint type を読み飛ばす分岐が、外側で
既に検証済みのオプション長 (`length == METRIC_CONTAINER_OPTION_LENGTH`)
ではなく、パケットの中身からそのまま読んだ `objLength`
(0-255、送信元が自由に設定できる) を `Buffer::Iterator::Next()` に
そのまま渡していた。DIO は本実装では未認証のため、隣接ノードが
`objLength = 255` のような値を仕込んだ DIO を送るだけで、debug
ビルドでは `NS_ASSERT(m_current + delta <= m_dataEnd)` (`buffer.h`)
が落ちてプロセスごと abort、NDEBUG ビルドではアサートなしにバッファ
末尾を越えて読み進む。オプション自体のサイズは呼び出し側で既に
確定しているので、`objLength` を信用せず
`METRIC_CONTAINER_OPTION_LENGTH - 4` (共通ヘッダ 4 バイト分を引いた
残りバイト数) だけ読み飛ばすように直した。

回帰テストとして `RplDioUnknownMetricTypeTestCase`
(`test/rpl-test-suite.cc`) を追加した。未知の mcType かつ
`objLength = 255` を持つ Metric Container オプションの直後に既知の
ETX オプションを続け、修正前のコードではこのテストが上記の
`NS_ASSERT` で落ちること、修正後は後続の ETX オプションが正しく
パースされることの両方を確認している。

**`m_pathEtx` がランクの floor-clamp 中は陳腐化する**

`SelectPreferredParent()` の `changed` 判定 (再選択の結果を適用するか
どうか) が `best != m_preferredParent || bestRank != m_rank` だけを
見ていた。ランクは `parent.rank + MinHopRankIncrease` で
floor-clamp されることがあり (13.5 節)、その状態が続く間はパス費用が
動いてもランクは動かないため、`changed` が false のまま早期 return
し、この node が次の DIO で advertise する `m_pathEtx` が更新され
なくなっていた。MRHOF かつ親が決まっている場合はパス費用の差分も
`changed` の判定に加えて修正した。

**`RankViaParent()` と `PathCostViaParent()` の重複計算**

`SelectPreferredParent()` はメインループ、ヒステリシスブロックの
双方で、同じ候補について `RankViaParent()` (内部で
`PathCostViaParent()` を呼ぶ) を呼んだ直後に、もう一度独立して
`PathCostViaParent()` を呼んでいた。`RankViaParent()` に
`uint32_t* pathCost` の out パラメータ (既定 `nullptr`) を追加し、
呼び出し側が計算済みのパス費用をそのまま受け取れるようにして、
二重計算を無くした。

**example: `LrWpanErrorModel` がフラグに関係なく全ノードに付く**

`rpl-6lowpan-simple.cc` で `LrWpanErrorModel` の生成/設定が
`--mrhof`/`--lql` の分岐より前にあり、フラグなしのデフォルト実行
(単なる到達性デモとして使われることを想定) でも実際にフレーム損失が
発生するようになっていた。LQL は RSSI (伝搬減衰だけで既に変動する)
由来なので実際に必要なのは MRHOF の ETX だけであり、
`LrWpanErrorModel` の設定を `if (mrhof)` の中に移した。

**`LrWpanLqiPeekTag` / `LrWpanRssiPeekTag` の重複**

13.3 節、14.2 節でそれぞれ追加した、実際の lr-wpan タグの中身を
TypeId 名前解決経由で読むためのスタンドインタグが、ペイロードの型
(`uint8_t` の LQI、`int8_t` の RSSI) が違うだけでほぼ同一の実装
だった。1 バイトのペイロードをそのまま (`uint8_t`) 保持する
`LrWpanPeekByteTag` 1 つにまとめ、RSSI 側の呼び出し元で
`static_cast<int8_t>` するように変更した。

**TypeId 解決失敗が無警告だった**

`LinkEtxFromPacket()`/`LinkLqlFromPacket()` は `lr-wpan` の
タグ TypeId が見つからない場合、無警告のまま中立値
(ETX 1.0 相当、LQL undetermined) にフォールバックしていた。
`librpl` が `liblr-wpan` にリンクしない構成 (13.3 節) では毎回
この経路を通るのが正常系なので警告ログにはせず、`NS_LOG_LOGIC`
(既定で出力されない) を追加するに留めた — 将来 lr-wpan 側でタグの
クラス名が変わってフォールバックが意図せず発動するようになった
場合でも、ログを有効にすれば追跡できるようにするため。

**見送った指摘: PHY 側での RSSI タグの無条件付与**

`src/lr-wpan/model/lr-wpan-phy.cc` の `EndRx()` は、RPL が
`LrWpanRssiTag` を使うかどうかに関わらず、受信した全フレームに
無条件でこのタグを付けている (`PdDataRequest()` 側で送信前に
剥がす処理も LQI/RSSI で 2 回の独立したスキャンになっている)。
ただし同じ関数はもともと LQI についても同様に全フレームで
インクリメンタルに計算・付与しており (`CheckInterference()` 経由)、
1 バイトのタグ追加はその既存コストに比べて無視できる。RPL を
使わない lr-wpan シミュレーションのためだけに新しい attribute
(例えば "RSSI タグを付けるか") を `src/lr-wpan` 側に追加するのは、
得られる効果に対してコアモジュールへの変更が過大と判断し、見送った。

## 14. RFC 6551 (LQL) の実装、および RSSI の取得

「LQL を実装、RSSI と LQL の対応は任意に変更できるようにすること」という
指示を受け、RFC 6551 の Link Quality Level (LQL) メトリック
(Routing-MC-Type=6、section 4.6) を追加した。ETX (13 節) との大きな違いは
2 点: LQL は RFC 上「recorded only」(記録専用) の Link metric であり
Objective Function がそこからランクを計算する対象ではないこと、そして
信号源が LQI (ETX) ではなく RSSI であること。

### 14.1 RFC 6551 の LQL オブジェクトのワイヤフォーマット

RFC 6551 の LQL Reliability Object は他の Routing Metric/Constraint
object と同じ 4 バイトの共通ヘッダ (MC-Type, Res+P+C+O+R, A+Prec,
Length) の後に、Res オクテット (1 バイト) + LQL sub-object (1 バイト、
上位 4 bit が Val、下位 4 bit が Counter) が続く。Val は 0 (undetermined)
から 7 (最悪) の整数で、1 が最良 (RFC 6551 の当該箇所を WebFetch で
複数回・複数の言い回しで取得し、"0 means undetermined and 1 indicates
the highest link quality" および "select the path with most links
reporting a LQL value of 3 or less" という記述が一致することを確認 —
値が小さいほど良い、という ETX と同じ方向性)。Counter は本来「パス上で
その LQL 値を持つリンクの本数」を数えるヒストグラム用のフィールドだが、
本実装はホップごとのスカラー値 (自分のプリファードペアレントへのリンク
1 本分) しか扱わないため、Counter は常に 1 を送信し、受信時は読み捨てる。

`RplDioHeader` は ETX 用の DAG Metric Container (`m_hasMetricContainer`/
`m_pathEtx`) とは独立に `m_hasLql`/`m_lql` を持ち、`Deserialize()` の
既存の Metric Container 分岐 (type 判定後、MC-Type でさらに分岐する
ループ) に `RPL_DAG_MC_LQL` のケースを追加する形で実装した。ETX と LQL
の object body はどちらも 2 バイトで DAG Metric Container のオプション
全体サイズが偶然一致する (8 バイト) ため、この既存分岐にそのまま乗せる
ことができた。1 つの DIO に ETX と LQL の両方の Metric Container を
同時搭載できることを `RplDioHeaderTestCase` で検証済み — 10 節で
「未対応」としていた「1 DIO に複数の Routing-MC-Type」はこれで解消。

### 14.2 RSSI の取得: ns-3 コアへの `LrWpanRssiTag` 追加

ETX の元になる LQI は既に `ns3::lrwpan::LrWpanLqiTag` として PHY が
受信フレームに付与しており (13.3 節)、そのまま読めた。RSSI は事情が
違う: `LrWpanPhy::EndPreamble()` で `m_rssi` (int8_t, dBm) として計算
されてはいるものの、パケットのタグにはならず、`PdDataIndicationCallback`
の引数として `LrWpanMac::PdDataIndication()` に渡り、最終的に
`McpsDataIndicationParams::m_rssi` に収まるだけで、そこから先
(`LrWpanNetDevice` が上位へ渡す一般的な `NetDevice::ReceiveCallback`
の署名にはこの手の付随情報を運ぶ余地が無い) で失われる。つまり LQI と
違い、RSSI は 6LoWPAN より上の層に届く手段が最初から存在しなかった。

対処として `src/lr-wpan/model/lr-wpan-rssi-tag.{h,cc}` を新設し、
`LrWpanLqiTag` と全く同じ形 (1 バイトの `Tag` サブクラス、
`AddAttribute`/`GetInstanceTypeId`/`Serialize`/`Deserialize` の並びまで
揃えた) で `LrWpanRssiTag` を追加した。`LrWpanPhy::EndRx()` の、LQI タグ
を読み出して `m_pdDataIndicationCallback` に渡す直前の箇所
(`lr-wpan-phy.cc`) で `currentPacket->AddPacketTag(LrWpanRssiTag(m_rssi))`
を 1 回呼ぶだけでよい — LQI が `CheckInterference()` で受信中に繰り返し
更新されるのに対し、RSSI はプリアンブル時点の 1 回きりの計測値なので
Peek+Replace は不要、Add だけで足りる。送信側 (`PdDataRequest()`) では
既存の「前回受信時の LQI タグを消す」処理の隣に RSSI タグを消す 1 行を
追加し、再送信時に受信時のタグを引きずらないようにした。

新規ファイル 2 つと `CMakeLists.txt` への追加 4 行、`lr-wpan-phy.cc` への
数行の追加のみで、既存の `lr-wpan`/`sixlowpan` の単体テスト
(`lr-wpan-*`、`sixlowpan-*`、計 15 スイート) はすべて無変更のまま
PASS しており、既存動作への影響は無い。

`librpl` からの読み取り方法は ETX の LQI タグ読み取り (13.3 節) と
全く同じ TypeId 名前解決 + `PacketTagIterator` の手法を踏襲しており、
今回も `liblr-wpan` への直接依存を増やしていない。

### 14.3 RSSI から LQL への対応を任意に変更可能にする

指示の核心部分。RFC 6551 の LQL は "The reliability value is computed by
the sending node according to a metric that is implementation specific"
と明記しており、閾値の取り方に唯一の正解が無いことを RFC 自身が認めて
いる。これを反映し、`RplRoutingProtocol::SetRssiToLqlMapping()` で
`Callback<uint8_t, double>` (RSSI dBm -> LQL 0-7) を丸ごと差し替え
られるようにした。組み込みのデフォルト実装 (`DefaultRssiToLql()`、
匿名名前空間) は単純な閾値テーブルで、802.15.4 級 LLN 無線の受信可能
範囲 (-106 dBm 付近が実用上の下限、`src/lr-wpan/examples/
lr-wpan-per-plot.cc` が使っている感度の数値を参考にした) に合わせて
おり、Wi-Fi や携帯網のような強い信号を前提にした一般的な RSSI 目盛りは
採用していない。あくまで「それらしいデフォルト」であり、実機やシナリオ
ごとに校正して `SetRssiToLqlMapping()` で置き換えることを前提とした
設計。`RssiToLql()` (public) はいま設定されているマッピングをそのまま
呼ぶだけの薄いラッパーで、単体テストからマッピング機構そのものを
(実際の RSSI タグ無しで) 直接検証できるようにするためだけに公開した。

なお `rpl-6lowpan-simple` 例で実際に測定した RSSI は、既定の 60 m 間隔で
-100 dBm 前後だった (10 m: -76 dBm、30 m: -90 dBm、60 m: -100 dBm、
90 m: -105 dBm — `LogDistancePropagationLossModel` の距離依存性通り、
単調に減衰している)。これは当初デフォルトテーブルとして用意していた
Wi-Fi 的な閾値 (-60〜-85 dBm) では全リンクが最悪値 (LQL=7) に張り付いて
しまうことを示しており、この LLN 向けの再校正 (現在のデフォルト値) に
至った直接のきっかけになった。RFC が「implementation specific」と
明言している理由を、まさにこのモジュール自身のデフォルト値選びで
再確認した形になる。

`SetRssiToLqlMapping()` が受け取るコールバックは丸ごと差し替え可能な
自由形式であり、0-7 の範囲を守る保証がない。コードレビューで、
`RssiToLql()` がその戻り値をそのまま返し、`RplDioHeader::SetLql()`
も範囲検証なしに `m_lql` へ代入していたことが見つかった。7 を超える
値を返すマッピングを設定すると、`RplDioHeader::Serialize()` の
`(m_lql << 4) | 0x1` で上位ビットが静かに切り詰められ、advertise
される LQL がワイヤ上で破損する。`RssiToLql()` (境界: ユーザー
コールバックの出口) と `RplDioHeader::SetLql()` (境界: DIO ヘッダの
公開 API) の双方に `RPL_LQL_WORST` へのクランプを追加した。あわせて
`RplDioHeader::Deserialize()` 側の LQL Val サブフィールド読み取り
(14.1 節、4 bit なので 0-15 になり得る) も同じ上限でクランプし、
`GetLql()` が文書化している 0-7 の範囲を受信経路でも保証するように
した。

### 14.4 LQL は経路選択に使わない

RFC 6551 が LQL を "recorded only" と位置付けている (13.1 節で言及した
Routing-MC-Type 一覧の取得時に確認) ことを根拠に、LQL は MRHOF のランク
計算や親選択には一切使わない。`RplRoutingProtocol::SendDio()` は
`EnableLql` attribute (既定 false、ワイヤフォーマットを変えない後方
互換のため MRHOF の `Ocp` と同じくオプトイン) が立っているときのみ、
自分のプリファードペアレントへのリンクの LQL を DIO に載せて advertise
する。ETX のようにホップごとに積算されるパスコストではなく、あくまで
「このノードから見た直近 1 ホップの記録」であり、受信側 (`HandleDio()`)
もこの意味論に合わせて「自分がその隣接ノードから測った LQL
(`parent.lql`、RSSI タグ由来)」と「その隣接ノードが DIO で自己申告した
LQL (`dio.GetLql()`、隣接ノードとその先の親との間のリンクについての
情報)」を混同しないよう、後者を `parent.lql` に書き込むことはしていない
— デシリアライズはするが、経路選択にも `parent.lql` の更新にも使わない
(パースの正しさのみ保証)。運用者や外部の監視ツールが DIO を横取りして
ネットワーク全体の品質マップを作る、といった診断用途を主眼に置いた
設計であり、ノード自身が能動的に使う値ではない。

### 14.5 テスト

`RplDioHeaderTestCase` を拡張し、同じ DIO に ETX と LQL の両
Metric Container を載せて往復させ、両方が壊れずに残ることを確認。
新設の `RplLqlMappingTestCase` は `RplRoutingProtocol` を単体で
(ノードもトポロジも使わず) 生成し、`RssiToLql()` でデフォルトテーブルの
境界値を確認したのち `SetRssiToLqlMapping()` でラムダに丸ごと差し替え、
差し替え後は新しいマッピングだけが使われる (デフォルトとの併用ではない)
ことを確認する。ETX のときと同様、`rpl-test` は `liblr-wpan` を
リンクしないため、実際の RSSI タグからの LQL 導出は単体テストの対象外
— 14.2 節の実行結果が唯一の end-to-end 検証である。

## 15. RFC 6550/6551/6553/6554 準拠監査、アドレス自動設定 (SLAAC/DAD)
    への移行、および RFC 6554 の重大ギャップ修正

RFC 6550 (RPL)、RFC 6551 (Routing Metrics)、RFC 6553 (RPI)、RFC 6554
(SRH) の原文を rfc-editor.org から取得し、本実装と突き合わせて監査した。
DIO/DAO/DAO-ACK/DIS のワイヤフォーマットと基本処理、DAG Metric Container
上の ETX/LQL (13, 14 節)、DODAG Configuration option、Target/Transit
Information option、non-storing mode の DAO、Rank 計算とループ回避、RPI
(12 節)、SRH のワイヤフォーマットとホップ処理は準拠済みと確認した。
10 節に記録済みの lollipop 比較未実装・RH3 アドレス圧縮未実装・RPI の
確認済みループを実際には止められない、の 3 件は優先度が低いため今回も
対象外、現状維持とした。今回対応したのは次の 2 件:

1. RFC 6550 6.7.10 節の Prefix Information option が未実装で、root の
   GUA/ULA プレフィックスを DIO で配布する経路自体が存在しなかった
   (アドレスは `Ipv6AddressHelper` による全ノード一括の静的固定割当)。
2. RFC 6554 4.2 節の、中継時の on-link 検証と SRH ループ検出が未実装
   だった。

### 15.1 Prefix Information Option の実装

`RplDioHeader` に `RPL_OPTION_PREFIX_INFO` (定義済みだったが未使用) の
Serialize/Deserialize を追加した。フィールドは RFC 6550 6.7.10 節の図
そのまま: Type(1) + Length(1) + PrefixLength(1) + Flags(1, 上位 2 bit が
L/A) + ValidLifetime(4) + PreferredLifetime(4) + Prefix(16) の計 28
バイト。RFC 4861 (Neighbor Discovery の PIO) には同じ並びに加えて
Reserved2 (4 バイト) があり計 32 バイトになるが、RFC 6550 の PIO には
それが無い。最初の実装ではここを混同して `PREFIX_INFO_OPTION_SIZE = 32`
としてしまい、`GetSerializedSize()` は 32 バイトを返すのに
`Serialize()` は 28 バイトしか書かないというサイズ不整合を起こし、
`rpl-6lowpan-simple` の実行中に別ノードの `Deserialize()` が
`NS_ASSERT failed, cond="m_current + delta <= m_dataEnd"` でバッファ
範囲外に落ちた。RFC 本文の ASCII art 図を直接引用させて確認し直し、
28 に修正して解消した。

### 15.2 root 自身のアドレス生成と DODAG 起動の非同期化

`RplRoutingProtocol` に `RootPrefix`/`RootPrefixLength` 属性を追加し、
`RplHelper::SetRoot()` のシグネチャを `SetRoot(node, prefix,
prefixLength = 64)` に変更した。root は `DoInitialize()` で
`Ipv6Address::MakeAutoconfiguredAddress()` (`AddAutoconfiguredAddress()`
が内部で使うのと同じ導出) で `RootPrefix` から自分の EUI-64 ベースの
アドレスを組み立て、`Ipv6L3Protocol::AddAddress()` で追加する。
`AddAddress()` は Duplicate Address Detection (RFC 4862) を自動的に
スケジュールする (`Icmpv6L4Protocol` の `DAD` 属性、既定 true) ため、
DODAG の起動 (`m_joined = true`、Trickle 起動、DODAGID の確定) は
`DoInitialize()` では行わず、`Icmpv6L4Protocol` の `"DadSuccess"`
TraceSource (`TracedCallback<const Ipv6Address&>`) に接続した
`HandleDadSuccess()` に移した。DAD が実際にアドレスの一意性を確認して
初めて、その上に DODAG を組み立てる設計である。

トレース接続時、`HandleDadSuccess(Ipv6Address address)` (値渡し) で
繋ごうとすると `Incompatible types` で `NS_FATAL` になった。
`TracedCallback` のシグネチャに合わせ `const Ipv6Address&` (参照渡り)
にする必要がある。

### 15.3 非 root ノードの SLAAC トリガーと PIO の転送

`JoinDodag()` で、受信した DIO が Prefix Information option を持ち A
フラグが立っていれば、`Ipv6L3Protocol::AddAutoconfiguredAddress()`
(標準の SLAAC エントリポイント) を呼ぶ。以後、この Prefix Information
option は自分が送信する DIO にもそのまま乗せて転送する
(`SendDio()`) — DODAG Configuration option と同じ「root が決め、
全ノードが継承して転送する」パターンである。

### 15.4 `GetGlobalAddress()` と TENTATIVE_OPTIMISTIC: 当初の設計が
     前提から誤っていた点

`GetGlobalAddress()` は当初 `iaddr.GetState() != TENTATIVE` の条件で
DAD 未完了のアドレスを除外する設計にしていた。ところが ns-3 コアの
`Ipv6InterfaceAddress` はデフォルトで `TENTATIVE_OPTIMISTIC` (RFC 4429
の Optimistic DAD) 状態を持ち、`AddAutoconfiguredAddress()` が作る
アドレスもこの状態のまま `AddAddress()` に渡る。`TENTATIVE` と
`TENTATIVE_OPTIMISTIC` は別の enum 値であり、上記の条件は後者を
除外しない。つまりこの実装は最初から (`GetGlobalAddress()` を
書いた時点から) DAD の完了を待たず、アドレス追加と同時に即座に
そのアドレスを使い始めていたことになる — ns-3 の SLAAC 実装自体が
「DAD 完了前から使ってよい」という楽観的 DAD の意味論で作られている
ためで、これは ns-3 コア側の一貫した設計であり、本実装のバグではない。

この事実に気づかず、非 root ノードにも root と同様
「`HandleDadSuccess()` が発火するまで最初の DAO 送信を待つべき」
という誤った前提で `SendDao()` の再試行を `HandleDadSuccess()` から
nudge する実装を一度追加した。結果、`RplDaoAckRetryTestCase` で
DAO 到着数が期待値 4 に対し実測 6 になった。原因を
`NS_LOG="RplRoutingProtocol=level_all"` のログで追跡したところ、
最初の DAO は (アドレスが `TENTATIVE_OPTIMISTIC` の時点で) 既に
成功して ACK まで受け取っていたにもかかわらず、1 秒後の
`DadTimeout` 到達時に nudge が無条件で再送をトリガーし、それが
ちょうど回線遮断後だったため ACK されず、リトライ・次回定期 DAO の
系列を丸ごと 1 サイクル分余分に生んでいた。nudge は完全に不要
だったと判明し、削除した。root 側の `HandleDadSuccess()` ゲート
(DODAG 起動を実際の DAD 完了まで待つ) は、root が名乗る DODAGID
という「一度確定したら全ノードに伝わる」性質上、より保守的な
設計として意図的に維持している (アドレスは使えても、まだ確定して
いないかもしれないものを DODAG の identity にはしない)。

### 15.5 `Ipv6AddressHelper::AssignWithoutAddress()` が必要だった理由

アドレス静的割当を完全に削除する過程で、`Ipv6AddressHelper::Assign()`
の呼び出し自体も削除したところ、全ノードで
`NS_ASSERT failed, cond="m_ptr", msg="Attempted to dereference zero
pointer"` が `DoInitialize()` 開始直後に起きた。`Assign()` は
アドレスを割り当てるだけでなく `Ipv6::AddInterface(device)` を呼んで
`Ipv6Interface` オブジェクト自体を作る役目も兼ねており、これを
省くとインターフェースが存在せず `m_ipv6->GetNetDevice(1)` 等が
軒並み落ちる。ns-3 コアに既にある `AssignWithoutAddress(devices)`
(インターフェース作成・アップ・トラフィックコントロール設定は行うが
グローバルアドレスの割当だけ省く) に切り替えて解消した。

### 15.6 RFC 6554 4.2 節: on-link 検証と ICMPv6 エラー送信

`RplIpv6ExtensionSourceRouting::Process()` で `RouteToNeighbour()` と
`RouteOutput()` が両方とも経路を返せなかった場合に、RFC 6554 4.2 節の
"a router MUST drop the datagram and SHOULD send an ICMPv6 Destination
Unreachable message with Code 7" に従い、
`Icmpv6L4Protocol::SendErrorDestinationUnreachable(malformedPacket,
srcAddress, RPL_ICMPV6_SRH_ERROR)` (`RPL_ICMPV6_SRH_ERROR = 7`、
`rpl-conf.h` に追加。ns-3 コアに Code 7 の名前付き定数は無い) を送る
よう変更した。

テストを書く過程で、`RouteToNeighbour()` が使う
`InterfaceForNeighbour()` に「一度も聞いたことのない隣接アドレスでも、
単一 RPL インターフェースのノードなら唯一の答えとしてそのインター
フェースを返す」というフォールバックが既にあることに気づいた
(コード自身のコメントに明記されている、本実装側の既存の意図的な
設計で、今回変更していない)。つまり単一インターフェースのノード
(LLN では通常のケース) では `RouteToNeighbour()` は事実上必ず経路を
返し、この on-link エラー経路は「対象のネクストホップが未知」では
発火しない。実際に発火するのは RPL インターフェースを 1 つも持たない
ノード (`m_ifcToSocket` が空) のときだけで、単体テストも
(`RplSourceRoutingProcessTestCase`) NetDevice を一切持たないノードを
別途用意してこの経路を検証している。

### 15.7 RFC 6554 4.2 節: SRH ループ検出

同じく `Process()` に、Routing Header の Address[] を Segments Left が
指すエントリを除いて走査し、「このノードに割り当てられたアドレスが
2 回以上、間に一致しないアドレスを 1 つ以上挟んで出現する」パターンを
検出する処理を追加した。検出したら
`icmpv6->SendErrorParameterError(malformedPacket, srcAddress,
Icmpv6Header::ICMPV6_MALFORMED_HEADER, ipv6Header.GetSerializedSize() +
offset + 2)` でエラーを送り `Ipv6L3Protocol::DROP_ROUTE_ERROR` として
ドロップする (Pointer の計算については 16.6 参照)。root の non-storing
経路計算 (`ComputeSourceRoute()`) はこの形の経路を単独では作らないため、
想定される発火条件は経路が古くなった (親が変わった後)、または改ざん
された場合に限られる。

### 15.8 テストと example の SLAAC 前提への全面書き換え

ユーザー指示により、静的割当は SLAAC に完全置換し、`rpl-test-suite.cc`
と `rpl-6lowpan-simple.cc` も全面的に書き換えた。`interfaces.GetAddress
(i, 1)` でグローバルアドレスを取得していた箇所は使えなくなるため、
`RplRoutingProtocol::GetGlobalAddress()` を private から public に
公開し、各テストは対応するノードの `RplRoutingProtocol` から直接
取得する形に変更した。DAD 分の遅延 (既定 `DadTimeout` = 1 秒) が
新たに乗るため、`RplPacketInfoProcessTestCase` (root の rank が
確定するのを待つ必要がある) 等、いくつかのテストの `Simulator::Stop()`
の秒数を実測値に基づいて調整した。`RplDaoAckRetryTestCase` は
`NS_LOG` でイベントのタイムスタンプを実際に採取し、DAO-ACK のリトライ
系列がどこに来るかを確認したうえで待ち時間と期待値を合わせている
(15.4 節の nudge 削除後の系列)。

### 15.9 検証結果

`./ns3 run "test-runner --suite=rpl --verbose"` で全ケース PASS
(既存ケースの書き換え分に加え、Prefix Information option の
シリアライズ往復、on-link 検証、SRH ループ検出の新規ケースを含む)。
`rpl-6lowpan-simple --mrhof --lql` で、root にのみ `RootPrefix`
(`2001:1::/64`) を設定した状態から 3 ノードの DODAG が形成され、
各ノードが DIO の Prefix Information option 経由の SLAAC で
`2001:1::ff:fe00:N` 形式のアドレスを得て、最終ノードから root への
ping が 5/5 (0% packet loss) で通ることを確認した。

## 16. RFC 6554 RH3 アドレス圧縮 (CmprI/CmprE) の実装

15 節の監査で対象外とした低優先度項目のうち、RH3 アドレス圧縮を実装した。
それまでの `RplSourceRoutingHeader` は CmprI/CmprE/Pad を常に 0 で送り、
すべてのアドレスを 16 バイト非圧縮で運んでいた。

### 16.1 圧縮復元に外部コンテキストが要らないと分かった経緯

RFC 6554 の圧縮は、一般には「処理時点でのパケットの IPv6 宛先アドレス」
から省略したプレフィックスバイトを復元する仕組みで、これは
`Header::Serialize(Buffer::Iterator)`/`Deserialize(Buffer::Iterator)` が
そもそも受け取れない外部コンテキストに依存する。実装前にこの点をユーザー
に確認し、一度は「Get/Set 系 API に参照アドレス引数を追加する」方針で
合意した。

しかし `RplRoutingProtocol::ComputeSourceRoute()`/
`PrepareOutgoingPacket()` を読み直したところ、本実装のアドレス配列には
常に成り立つ不変条件があるとわかった: 末尾より前のエントリ (中継ホップ)
は `ComputeSourceRoute()` が `LinkLocalOf()` で構築するため常にリンク
ローカル、末尾のエントリだけが実宛先で、`PrepareOutgoingPacket()` が
`addresses.back() = dst` で上書きする時点で `dst` は非リンクローカル
(グローバル) と確定している。中継処理
(`RplIpv6ExtensionSourceRouting::Process()`) がエントリを書き換える
ときも、書き込まれる値は常にその中継ノード自身のリンクローカル
アドレスで、この不変条件は経路全体を通じて崩れない。

リンクローカルの上位 8 バイトは `fe80:0000:0000:0000` という
実装非依存の固定値 (`Ipv6Address::IsLinkLocal()` が
`CombinePrefix(Ipv6Prefix(64)) == "fe80::0"` で判定するのと同じ、
`RplRoutingProtocol::LinkLocalOf()` の `linkLocalPrefix` とも同一)。
よって「そのエントリがリンクローカルなら fe80:: プレフィックスを省略、
そうでなければ (グローバル/マルチキャスト) 圧縮しない」という、
エントリの値だけを見て決める方式が、外部コンテキストなしに常に
正しく成立する。RFC の一般的な「処理時点の宛先アドレスからプレフィックス
を復元する」規則とも矛盾しない: 本実装で圧縮対象になるエントリを処理する
瞬間の実際の宛先アドレスは、常にそのエントリ自身と同じ fe80:: プレフィ
ックスを持つので、別の RFC 6554 実装がこのモジュールの送るパケットを
読んでも同じように正しく復元できる。この発見により、結局 Get/Set API の
シグネチャ変更は不要になった。

### 16.2 CmprI/CmprE の決め方、Pad が常に 0 になる理由

- CmprI (末尾より前のエントリ全体に適用): `addresses[0..n-2]` が全て
  リンクローカルなら 8、そうでなければ 0
- CmprE (末尾エントリだけに適用): `addresses[n-1]` がリンクローカル
  なら 8、そうでなければ 0

実運用 (`PrepareOutgoingPacket()` が作る配列) では常に CmprI=8,
CmprE=0 になる。CmprI/CmprE は 0 か 8 の 2 値しか使わないため、
ヘッダーサイズは `8 + (n-1)*(16-CmprI) + (16-CmprE)` で必ず 8 の倍数
になり (16-0=16, 16-8=8 はどちらも 8 の倍数)、Pad は常に 0 で済む。
`RplSourceRoutingHeader::Cmpri()`/`Cmpre()` (private) は `m_addresses`
の現在値から都度計算するだけで、内部状態としてキャッシュしない。これに
より `SetAddress()` (中継時の書き換え) は無変更のまま、次に
`Serialize()` されるときに新しい値へ自動的に追従する。実際、中継が
最後から 2 番目のホップを処理するとき、末尾エントリは (それまでの
グローバルな実宛先から) この中継ノード自身のリンクローカルアドレスへ
上書きされるため、その次の 1 ホップだけ CmprE=8 に切り替わり、末尾の
16 バイトも追加で圧縮される — 狙って作った副次効果ではなく、
「都度計算」という設計から自然に出てくる正しい挙動。

### 16.3 Deserialize の防御的実装

本実装が自分自身では決して送らない CmprI/CmprE 値 (0 と 8 以外、
4 bit フィールドなので最大 15) を持つ手作りパケットが来ても範囲外
読み出しをしないよう、fe80:: 定数からのコピーは 8 バイトでクランプし、
残りは 0 埋めする。また `Deserialize()` の戻り値 (呼び出し元の
`Packet::RemoveHeader()` がパケットから何バイト取り除くかはこの
戻り値だけで決まり、ローカルな `Buffer::Iterator` の最終位置は見ない)
は、復元したアドレスから `GetSerializedSize()` を再計算した値ではなく、
ワイヤ上の `Hdr Ext Len` から直接 `(hdrExtLen + 1) * 8` として求める。
理由: 本実装が送らない CmprI (0/8 以外) を含むヘッダーを復元すると、
再構築されたアドレスの上位バイトが偶然 fe80:: と一致しないことがあり
(例えば CmprI=4 なら上位 4 バイトだけ fe80:: 定数から埋め、残り 4
バイトはワイヤ上の任意の値になる)、その場合 `IsLinkLocal()` が偽に
なって `Cmpri()`/`Cmpre()` の再計算結果が元の値と食い違う。ワイヤの
`Hdr Ext Len` を直接信頼すれば、この食い違いを気にする必要がない。

### 16.4 転送のたびに Payload Length を再計算する必要がある

16.2 節で述べた「最後から 2 番目のホップだけ末尾エントリの CmprE が
8 に切り替わり、末尾の 16 バイトも追加で圧縮される」という挙動は、
その通りヘッダーのシリアライズサイズをホップごとに変える。
`RplIpv6ExtensionSourceRouting::Process()` は `routingHeader.SetAddress()`
で書き換えた後 `p->AddHeader(routingHeader)` で再シリアライズするが、
当初はここで IPv6 header 側の Payload Length を据え置いたまま
`SendRealOut()` していた。CmprE が 0→8 に切り替わるホップでは実際の
ペイロードが 8 バイト短くなるため、ワイヤ上の Payload Length が実サイズ
より大きいまま送出される。6LoWPAN の IPHC がこのフィールド自体を圧縮で
落として送受信の両側で毎回計算し直すため実害が (この構成では) 隠れて
いたが、pcap を直接読む場合や 6LoWPAN を介さない素の IPv6 リンクでは
壊れたまま出る。`SetAddress()` 直後、`prefix` (HbH 等の前置き + 更新後
SRH + 後続ペイロード、つまり IPv6 header の直後から先頭全体) が確定した
時点で `ipv6header.SetPayloadLength(prefix->GetSize())` を呼ぶよう修正。

### 16.5 テスト

`RplSourceRoutingHeaderTestCase` (両アドレスともリンクローカル、
CmprI=8/CmprE=8) の期待サイズを `8+2*16` から `8+8+8` に更新。新設の
`RplSourceRoutingCompressionTestCase` で、実運用と同じ形
(リンクローカルな中継ホップ 2 つ + グローバルな最終宛先、CmprI=8/
CmprE=0) と、単独のグローバルアドレス (直接の孫ノード向け、圧縮
なし) の両方でサイズ計算とラウンドトリップの一致を確認。
`RplSourceRoutingProcessTestCase` の「Segments Left already zero」
ケース (`{fe80::4}` 単体、CmprE=8) の期待消費バイト数を `8+16` から
`8+8` に更新。`RplDodagFormationTestCase` の下り方向パケットの
アサーション (`leafAddress` がグローバルなので CmprE=0、`8+16` の
まま) は無変更で PASS することを確認した — 実運用のグローバル最終
宛先は圧縮されないことの回帰確認になっている。
`rpl-6lowpan-simple --mrhof --lql` で DODAG 形成 + ping 5/5
(0% packet loss) が従来通り通ることを確認 (圧縮は
`RplIpv6ExtensionSourceRouting::Process()` から見て完全に透過的)。

### 16.6 ICMPv6 Parameter Problem の Pointer が IPv6 header 分ずれていた

`Process()` の 2 箇所 (15.7 の SRH ループ検出、および Segments Left が
アドレス数を超える「malformed header」判定) は `SendErrorParameterError()`
の `ptr` 引数に `offset + N` (`offset` は `packet`/`p` と同じ、拡張ヘッダー
チェーンの先頭、つまり IPv6 header の直後からの相対位置) を渡していた。
RFC 4443 section 3.4 の Pointer は「invoking packet 内でのオクテット
オフセット」で、ここでの invoking packet は `malformedPacket`
(`packet->Copy(); malformedPacket->AddHeader(ipv6Header);` で作られる、
IPv6 header を前置きした完全なパケット)。`offset` はその IPv6 header
の分だけ短く、`ipv6-l3-protocol.cc` の同種の呼び出し (`Receive()` の
Unknown Next Header 処理) は `ip.GetSerializedSize() + nextHeaderPosition`
と明示的に加算しているのに対し、ここではそれが欠けていて Pointer が
40 (IPv6 header の固定長) だけ手前を指していた。両呼び出しに
`ipv6Header.GetSerializedSize()` を足して修正。ICMPv6 Parameter Problem
は経路上のデバッグ用の診断情報であり、ドロップ自体の判定・処理には
関わらないため、実害は「間違った位置を指すエラーメッセージが飛ぶ」
ことに留まる。

## 17. DIO/DAO オプション読み出しが宣言サイズだけを見ていた (境界外読み出し)

`RplDioHeader`/`RplDaoHeader` の `Deserialize()` はオプションを
`while (!i.IsEnd())` で走査し、`type`/`length` (Type/Length フィールド、
共に相手が送ってきた値をそのまま信用する) を読んだ後、各オプション種別
ごとに `length == 対応する *_OPTION_LENGTH` かどうかだけを確認して本体を
読んでいた。`length` が本物と一致してさえいれば、パケットが実際にそれだけ
残っているかは一度も検証していない — 送信側が正直な `length` を書いた
まま、その後ろが実際には切り詰められている (伝送中に壊れた、あるいは
偽装された) パケットが来ると、`Buffer::Iterator::ReadU8()` 等が
バッファの終端を越えて読む。`PeekU8()` 自身の範囲チェックは
`NS_ASSERT_MSG` で、デバッグビルドでは検知して落ちるが、最適化ビルドでは
コンパイルごと消える (ns-3 の `NS_ASSERT` 系マクロの通常の挙動) ため、
そこでは範囲外メモリがそのまま読まれ、一部はオプションのフィールド値
としてそのまま使われる。

対処: `length` を読んだ直後、DIO/DAO 両方の `Deserialize()` に
`i.GetRemainingSize() < length` のガードを追加し、満たなければそこで
走査を打ち切る (以降のオプションは全て未知として扱う、既存の
「途中で `IsEnd()` になったら打ち切る」経路と同じ扱い)。`length` バイト
分の存在を一度確認すれば、それ以降の各分岐 (DAG Configuration、DAG
Metric Container、Prefix Information、Target、Transit、未知オプションの
`i.Next(length)`) は全て安全になる。

回帰テストとして `RplDioTruncatedOptionTestCase` を追加: DAG
Configuration option (type 4, 本物の Length 14) を、Length はそのままに
本体を 4 バイトで打ち切ったパケットを渡し、`HasDagConfiguration()` が
`false` のまま (壊れた本体が完全なものとして読まれていない) であることを
確認する。
