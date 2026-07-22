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
- **既知の非対応事項**: RFC 6553 (Hop-by-Hop header 内 RPL Option) は
  未実装。storing mode (MOP=2) は方針により対象外。RH3 アドレス圧縮
  (CmprI/CmprE) 未実装、6LoWPAN NHC 圧縮も Routing Header では効かない
  (11 節)。

## 11. ns-3 コアで見つかった既存バグ 2 件 (SRH 実装作業中に発覚)

正確な RH3 実装に切り替えた際、これまで一度も実運用パスを通っていなかった
ns-3 コアの Routing Header 関連コードで、独立した既存バグを 2 件発見・修正した。
どちらも RPL 固有ではなく、RFC 2460 RH0 (`Ipv6ExtensionLooseRouting`) を
6LoWPAN 経由で使うだけでも再現する。

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
