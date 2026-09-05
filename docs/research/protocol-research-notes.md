# 协议与核级接口研究笔记

> 用途：为协议组合器、总线适配器和长时间测试设计提供一份可核对的参考资料。
>
> 资料访问日期：2026-09-06。本文中的“支持”只表示资料明确描述的接口或集成方式；协议本身存在于 SoC wrapper、互连或适配器中时，不将其泛化为 CPU 核的原生支持。
>
> 写入范围说明：受工作区修改范围限制，以下两份参考文档合并在本文件中；本次只新增本文件，不修改源码、配置或测试。

## 参考文档一：常用片上互连协议

### 1. 阅读约定和横向比较

本文把一次事务分解为“请求被接受”和“响应被接受”两个可能不同的事件。对 `valid/ready` 类接口，`fire = valid && ready` 且发生在时钟上升沿；对 APB、AHB、Wishbone 等接口，使用各自规范定义的完成条件。下面的“安全不变量”是适合写成断言或形式检查的协议不变量，不能替代地址权限、防火墙、隔离和密钥管理等系统安全机制。

| 协议 | 主要传输形态 | 请求接受/完成 | 并发和顺序的主要特征 | 地址或安全属性注意事项 |
|---|---|---|---|---|
| APB4 | 非流水、单次寄存器访问 | `PSEL` setup 后进入 `PENABLE` access；`PREADY=1` 时完成 | 无 ID、无突发；通常一次只挂一个访问 | `PSTRB`、`PPROT` 是 APB4 增量；权限仍需由从设备/防火墙执行 |
| AXI4-Lite | 五个独立单拍通道 | 每个通道 `VALID && READY` | 无 ID、无突发；不能依赖 ID 做乱序匹配 | `AxPROT` 只是事务属性，不自动形成访问控制 |
| AXI4 | 五个独立通道、可突发 | 每拍分别 `VALID && READY` | ID、突发、多个 outstanding；同 ID 有顺序约束 | `AxPROT/AxCACHE/AxQOS` 等必须按互连语义保留或明确丢弃 |
| AHB-Lite | 地址/控制与数据阶段流水重叠 | `HREADY=1` 时当前传输完成 | 单 master、无事务 ID；可有连续 `SEQ` 突发 | `HPROT` 和 AHB5 的 `HNONSEC` 取决于版本/profile |
| TileLink-UL | A、D 两个 decoupled 通道 | A/D 各自 `valid && ready` | `source` 用于匹配 outstanding；UL 是单 beat | `a_mask`、`d_denied`、`*_corrupt` 不得静默丢失 |
| OBI | 地址请求/授权 + 响应 | A 通道 `req/gnt`；R 通道 `rvalid` | 点到点；ID、sideband 和 outstanding 数由版本/profile决定 | OBI 通常没有 AXI 式 `rready`；消费时序必须核对版本 |
| Wishbone Classic | `CYC` 包住一个或多个 `STB` 传输 | `ACK/ERR/RTY` 终止当前 `CYC && STB` | Classic 通常单次；B4 还定义可选 block/pipelined 形式 | `SEL` 是字节选通；`RTY` 的系统语义需要双方约定 |
| Avalon-MM | 灵活的 host/agent memory-mapped 接口 | `waitrequest=0` 接受请求；读数据可由 `readdatavalid` 返回 | 并发、读延迟、突发均由 interface properties/profile决定 | 地址通常是 word address；Intel Platform Designer 负责很多集成属性 |
| AXI4-Stream（补充） | 无地址的流/包 | `TVALID && TREADY` 每拍传输 | 按流顺序；`TLAST` 标记包边界 | 不能把它直接当 memory-mapped AXI；需 DMA/FIFO/描述符桥接 |

协议规范通常只规定传输合法性，不保证“某个地址可以被某个特权级访问”。因此，`PPROT`、`AxPROT`、`HPROT/HNONSEC`、OBI 的 `prot` 或 TileLink 的 user/安全扩展，必须与 SoC 的地址区域表和防火墙策略共同验证。

### 2. APB4

#### 2.1 信号

- 时钟/复位：`PCLK`、`PRESETn`。
- 地址/控制：`PADDR`、一个或多个 `PSELx`、`PENABLE`、`PWRITE`。
- 写/读数据：`PWDATA`、`PRDATA`。
- 完成/错误：`PREADY`、`PSLVERR`。
- APB4 增加或规范化的属性：`PSTRB`（写字节选通，宽度通常为 `PWDATA` 字节数）和 `PPROT[2:0]`（保护/安全/指令数据属性）。

#### 2.2 事务状态机和时序

```text
IDLE --PSEL=1--> SETUP --下一拍 PENABLE=1--> ACCESS
  ^                                      |
  |--------完成：PREADY=1---------------|
                       PREADY=0：留在 ACCESS 等待
```

在 `SETUP` 周期，主设备置 `PSEL=1`、`PENABLE=0`，同时给出地址、方向、写数据、`PSTRB` 和 `PPROT`。下一周期进入 `ACCESS`，置 `PENABLE=1`。只要 `PREADY=0`，主设备必须保持 access 控制和载荷；在 `PREADY=1` 的上升沿采样 `PRDATA` 和 `PSLVERR`，然后回到 `IDLE`，或在同一选中从设备上进入下一个 setup 周期形成 back-to-back 访问。最短传输是一个 setup 周期加一个 access 周期；APB 不提供 AXI 式流水、ID、outstanding 或 burst。

#### 2.3 握手、时序和安全不变量

1. `PENABLE` 只能在已经出现 setup 的下一周期及后续 access 周期为高；不能从 IDLE 直接跳到 access。
2. 在 `PENABLE=1 && PREADY=0` 时，`PADDR`、`PWRITE`、`PWDATA`、`PSTRB`、`PPROT` 以及选中的 `PSELx` 保持不变。
3. 一次完成只对应一次 `PSEL && PENABLE && PREADY`；从设备不能在 setup 周期用 `PREADY` 提前完成。
4. `PSLVERR` 只在 access 完成时解释；写操作的 `PSTRB=0` 或未实现的字节 lane 必须由从设备或适配器按系统约定处理。
5. 复位期间不得产生有效访问；多个 `PSELx` 同时有效属于译码/互连错误。

#### 2.4 常见桥接方式

- AXI4-Lite/AHB-Lite → APB：桥接器缓存一个地址/数据请求，串行发出 APB setup/access；把 AXI 的 `VALID/READY` 或 AHB 的 `HREADY` 转换为 APB `PREADY`，把 `PSLVERR` 转换为 `BRESP/RRESP` 或 `HRESP`。
- AXI4 → APB：必须拆分 burst、字节 lane 和可能的多个 outstanding，不能把 AXI burst 直接连到 APB。
- OBI/Wishbone/Avalon-MM → APB：通常使用单 outstanding FSM，映射 `be/SEL/byteenable` 到 `PSTRB`，并明确错误、超时和不支持的访问。
- APB → 更宽或可并发总线：需要响应队列、地址/字节地址转换和对读写返回顺序的约束；简单寄存器从设备通常只需要 APB slave，不需要反向桥。

#### 2.5 版本边界与来源

APB4 特性与 APB5/APB3 并不相同：`PSTRB`、`PPROT` 应按 APB4 版本检查，APB5 的唤醒、用户、奇偶校验等扩展不应无条件假定存在。

- Arm，*AMBA APB Protocol Specification*，IHI 0024（当前文档页，包含版本导航）：<https://developer.arm.com/documentation/ihi0024/latest/>；直接文档：<https://documentation-service.arm.com/static/63fe2c1356ea36189d4e79f3>；访问日期：2026-09-06。

### 3. AXI4-Lite

#### 3.1 信号

- 全局：`ACLK`、`ARESETn`。
- 写地址通道 AW：`AWADDR`、`AWPROT`、`AWVALID`、`AWREADY`。
- 写数据通道 W：`WDATA`、`WSTRB`、`WVALID`、`WREADY`。
- 写响应通道 B：`BRESP`、`BVALID`、`BREADY`。
- 读地址通道 AR：`ARADDR`、`ARPROT`、`ARVALID`、`ARREADY`。
- 读数据/响应通道 R：`RDATA`、`RRESP`、`RVALID`、`RREADY`。

AXI4-Lite 是 AXI4 的 memory-mapped 子集：每次访问是单 beat，不带 AXI4 的 burst 控制和事务 ID。数据宽度、地址宽度和是否允许某些可选属性仍是接口配置，不应从协议名称推断。没有 ID 意味着不能依赖 ID 区分乱序返回；适配器常把它收敛成单 outstanding，但若上游/互连允许排队，也必须保持规范要求的响应顺序。

#### 3.2 事务状态机和握手

```text
写：AW_WAIT --AW fire--> AW_ACCEPTED --+
     W_WAIT  --W fire --> W_ACCEPTED ---+--> B_WAIT --B fire--> IDLE

读：AR_WAIT --AR fire--> R_WAIT --R fire--> IDLE
```

AW 和 W 是独立通道，可以先后任意到达；只有两者都被接受后，slave 才能产生 B 响应。AR 被接受后由 R 返回数据和 `RRESP`。每个通道在上升沿 `VALID && READY` 时传输；发送方在 `VALID=1 && READY=0` 时保持地址、数据、字节选通和响应字段不变。发送方不能为了等待 `READY` 而禁止 `VALID`，否则可能与只在看到 `VALID` 后才给 `READY` 的接收方死锁；`READY` 可以早于 `VALID` 拉高。

#### 3.3 安全不变量

1. B 响应不能早于同一写事务的 AW 和 W 都被接受；R 响应不能早于 AR 被接受。
2. 任一通道发生 stall 时，该通道 payload 和 `VALID` 语义稳定；复位释放前后不得伪造一次 fire。
3. `WSTRB` 只表示有效写 byte lane，不能被桥接器误当成地址对齐信息；未选中的 lane 不应修改寄存器。
4. `BRESP/RRESP` 必须被消费方用 `BREADY/RREADY` 接受后才能结束；错误响应不可被转换成成功响应。
5. 由于没有 ID，适配器不得产生需要按事务 ID 重新排序的返回；不支持的并发必须反压或显式排队。
6. `AWPROT/ARPROT` 必须随地址请求保存到从设备或权限检查点；它们不是自动的安全边界。

#### 3.4 常见桥接方式

- AXI4-Lite → APB/AHB-Lite：缓存 AW/W 的任一先到部分，合并后发起目标总线单次访问；目标总线完成后生成 B/R。
- AXI4 → AXI4-Lite：将 burst 拆成多个单拍，处理 `WSTRB`、地址递增、ID 与返回顺序；不支持的 burst、锁或原子操作必须拒绝或由上游禁止。
- AXI4-Lite ↔ TileLink-UL/OBI/Wishbone/Avalon-MM：把五通道状态映射成目标总线的请求/响应 FSM；至少保留 byte enable、错误、地址单位和保护属性。

#### 3.5 版本与来源

AXI4-Lite 的字段和可选属性随 AMBA issue、互连 IP 和配置变化；本节以 Arm AXI/ACE 规范中的 AXI4-Lite 子集为准，不把它等同 AXI5-Lite 或某个厂商的寄存器总线。

- Arm，*AMBA AXI and ACE Protocol Specification*，IHI 0022（官方文档页）：<https://developer.arm.com/documentation/ihi0022/latest/>；规范 PDF：<https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/IHI0022H_amba_axi_protocol_spec.pdf?hash=6325311012DDADF238C35A6C0FD734E520754F82&la=en&revision=71bd7c57-2ed7-487b-bc3e-68c4ab56fa5f>；访问日期：2026-09-06。

### 4. AXI4

#### 4.1 信号

AXI4 仍由五个独立通道组成，每个通道都有 `VALID/READY`：

- AW：`AWID`、`AWADDR`、`AWLEN`、`AWSIZE`、`AWBURST`，以及可选/配置的 `AWLOCK`、`AWCACHE`、`AWPROT`、`AWQOS`、`AWREGION`、`AWUSER`。
- W：`WDATA`、`WSTRB`、`WLAST`、可选 `WUSER`。AXI4 不使用 AXI3 的 `WID`。
- B：`BID`、`BRESP`、可选 `BUSER`。
- AR：`ARID`、`ARADDR`、`ARLEN`、`ARSIZE`、`ARBURST`，以及对应的 `ARLOCK`、`ARCACHE`、`ARPROT`、`ARQOS`、`ARREGION`、`ARUSER`。
- R：`RID`、`RDATA`、`RRESP`、`RLAST`、可选 `RUSER`。

`AxLEN/AxSIZE/AxBURST` 描述 burst，`AxID` 允许一个接口管理多个 outstanding；具体 ID 宽度、数据宽度、是否实现锁/原子/用户字段是 profile 或 IP 配置。

#### 4.2 事务状态机、握手和时序

```text
写地址：AW_VALID/READY fire ─┐
写数据：W_VALID/READY fire ──┼─> 目标完成/错误 ─> B_VALID/READY fire
                              │       （W beats 直到 WLAST）
读地址：AR_VALID/READY fire ─────────> R beats（最后一拍 RLAST）
```

五个通道可以独立前进，写地址与写数据没有固定先后关系。每次 fire 只消费当前 beat；burst 的 W/R beat 依次传输，最后 beat 用 `WLAST/RLAST` 标记。`VALID=1 && READY=0` 时，源端保持该通道的所有 payload 不变；接收方可以预先拉高 `READY`。响应端必须根据协议的 ID 和顺序规则返回：同一 ID 的事务保持要求的顺序，不同 ID 是否乱序取决于系统约束和实现。

#### 4.3 安全不变量

1. `BVALID` 只能对应已经接受的 AW 和完整 W burst；`RVALID` 只能对应已经接受的 AR，且 `RLAST` 恰好标记该 burst 的最后一拍。
2. burst 长度与 `AWLEN/ARLEN` 一致，beat 大小与 `AxSIZE` 一致，地址递增/回绕与 `AxBURST` 一致；一次 burst 不得跨越 4-KB 边界。
3. 每个 ID 的返回 ID、响应数据和错误状态匹配原请求；桥接器不得用一个 ID 的完成释放另一个 ID 的资源。
4. 所有 stalled channel 的地址、数据、strobes、LAST、ID 和属性稳定；禁止依赖对端 `READY` 才首次产生 `VALID`。
5. `AxPROT`、`AxCACHE`、锁/原子和 user 字段必须被保留、明确降级或拒绝，不能无记录地丢失。
6. 互连的 outstanding 计数、FIFO 深度和背压逻辑必须保证响应不会丢失；复位要清除所有未完成事务的状态。

#### 4.4 常见桥接方式

- AXI4 → AXI4-Lite/APB/AHB-Lite：在桥内建立 burst 拆分器和 ID/响应队列，把每个 beat 变成目标总线单次传输，最后合成 B/R。
- AXI4 ↔ TileLink：常见于 SoC 互连和 DRAM 外设；需映射 source/ID、byte mask、burst/多 beat、denied/corrupt 和顺序语义。
- AXI4 ↔ OBI/Wishbone/Avalon-MM：通常限制为单 outstanding 或增加事务表；将 `WSTRB`/mask/byteenable 映射并处理目标协议不同的错误和返回延迟。
- AXI4 ↔ AXI4-Stream：不是简单信号重命名；需 DMA、FIFO 或描述符引擎把地址事务转换成数据流，反向亦然。

#### 4.5 版本与来源

本节按 Arm IHI 0022 的 AXI4 定义描述，AXI5、ACE、CHI 的原子/一致性扩展另有版本边界。某个 CPU 文档声称“AXI5”不意味着它实现全部 AXI5 可选通道或能够直接连接任意 AXI4/AXI5 设备。

- Arm，*AMBA AXI and ACE Protocol Specification*，IHI 0022：<https://developer.arm.com/documentation/ihi0022/latest/>；规范 PDF：<https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/IHI0022H_amba_axi_protocol_spec.pdf?hash=6325311012DDADF238C35A6C0FD734E520754F82&la=en&revision=71bd7c57-2ed7-487b-bc3e-68c4ab56fa5f>；访问日期：2026-09-06。

### 5. AHB-Lite

#### 5.1 信号

- 时钟/复位：`HCLK`、`HRESETn`。
- 地址/基本控制：`HADDR`、`HTRANS`、`HWRITE`、`HSIZE`、`HBURST`、`HPROT`。
- 数据：`HWDATA`、`HRDATA`。
- 完成/响应：`HREADY`、`HRESP`；实现内部常见 `HREADYOUT`。
- 可选锁和安全属性：`HMASTLOCK`；在较新的 AHB5 profile 可能有 `HNONSEC`。AHB-Lite 是单 master 变体，因此不要把完整 AHB 的仲裁/多 master 信号误列为 AHB-Lite 必需接口。

#### 5.2 事务状态机和时序

`HTRANS` 有 `IDLE`、`BUSY`、`NONSEQ`、`SEQ` 四种编码。一次独立传输以 `NONSEQ` 开始；同一 burst 的后续传输使用 `SEQ`；`BUSY` 不代表有效数据传输。AHB 的地址/控制阶段与前一传输的数据阶段可以重叠，形成流水：当当前传输的 `HREADY=0` 时，主设备必须保持当前地址和控制，直到该传输在 `HREADY=1` 的上升沿完成，并采样 `HRESP`/读数据。

```text
IDLE/NONSEQ --地址控制--> DATA_WAIT
                         | HREADY=0：保持当前 transfer
                         | HREADY=1,HRESP=OKAY/ERROR：完成
                         +--> 下一拍 SEQ/NONSEQ 或 IDLE
```

#### 5.3 握手、时序和安全不变量

1. 只有 `HTRANS=NONSEQ/SEQ` 且 `HREADY` 最终为高时才完成有效传输；`IDLE/BUSY` 不应产生数据副作用。
2. `HREADY=0` 的所有等待周期中，`HADDR`、`HTRANS`、`HWRITE`、`HSIZE`、`HBURST`、`HPROT`、锁/安全属性保持稳定；写数据也必须按数据阶段保持。
3. `HRESP=ERROR` 必须终止或报告当前传输；桥接器不能把错误变为 `OKAY`。
4. `HSIZE`、地址对齐、`HBURST` 和 `HTRANS` 序列必须一致；不支持的 burst 要拆分或返回错误。
5. AHB-Lite 的单 master 假设必须在互连边界成立；多 master 需要额外的 AHB 仲裁层，不能直接声称仍是单一 AHB-Lite 链路。
6. `HPROT/HNONSEC` 只能作为安全检查输入，不能替代从设备的地址权限检查。

#### 5.4 常见桥接方式

- AHB-Lite → APB：经典 AMBA 桥，缓存 AHB 地址/写数据并生成 APB setup/access；把 APB wait/error 反向形成 `HREADY/HRESP`。
- AXI4/AXI4-Lite ↔ AHB-Lite：把 AXI 通道和 ID/突发约束收敛到 AHB 的流水传输，或把 AHB burst 拆到 AXI 单拍；需要处理 AHB 的 `BUSY`、`HREADY` 和 AXI 的独立 AW/W。
- OBI/Wishbone/Avalon-MM → AHB-Lite：用单 outstanding FSM 将 grant/waitrequest/ack 转为 AHB 的等待；保留 byte enable、保护属性和错误。

#### 5.5 版本与来源

`HNONSEC` 等字段属于 AHB5 或相应 profile，不能回填到只实现 AHB-Lite 早期版本的设备。使用具体 IP 时要同时核对 AHB-Lite 版本、数据宽度和 burst 支持。

- Arm，*AMBA 5 AHB Protocol Specification*，IHI 0033：<https://developer.arm.com/documentation/ihi0033/latest/>；AMBA 3 AHB-Lite 规范入口：<https://developer.arm.com/docs/ihi0033/a/amba-3-ahb-lite-protocol-specification-v10>；访问日期：2026-09-06。

### 6. TileLink-UL

#### 6.1 信号和消息

TileLink-UL（Uncached Lightweight）使用 A、D 两条 decoupled 通道；每条通道有 `valid`、`ready` 和消息 payload。常见 RTL bundle 字段为：

- A 请求：`a_opcode`（`Get`、`PutFullData`、`PutPartialData`）、`a_param`、`a_size`、`a_source`、`a_address`、`a_mask`、`a_data`、`a_corrupt`。
- D 响应：`d_opcode`（`AccessAck` 或 `AccessAckData`）、`d_param`、`d_size`、`d_source`、可选/按 profile 出现的 `d_sink`、`d_denied`、`d_data`、`d_corrupt`。
- 全局：时钟/复位；具体生成器可能把 `a_valid/a_ready`、`d_valid/d_ready` 展平为端口。

UL 是最小的非一致性单 beat 子协议；不包含 TL-C 的 B/C/E 一致性通道，也不应把 TL-UH 的原子、hint 或更复杂操作直接当成 UL 能力。`a_source`/`d_source` 用于将 response 对回 request，source 宽度和允许的 outstanding 数由节点实现决定。

#### 6.2 事务状态机和握手

```text
A_IDLE --a_valid && a_ready--> OUTSTANDING[source]
                                   |
             Get -----------------+--> D_ACCESS_ACK_DATA
             Put -----------------+--> D_ACCESS_ACK
                                   |
                         d_valid && d_ready --> A_IDLE/下一个请求
```

Manager 在 A 通道发出合法请求，只有 `a_valid && a_ready` 的上升沿才算接受。等待 `a_ready` 时必须保持 A payload。Subordinate 完成读时产生带数据的 `AccessAckData`，完成写时产生 `AccessAck`；D payload 在 `d_valid && !d_ready` 时保持。允许多 outstanding 的 manager 可以同时维护多个 source，但同一 source 在旧事务完成前不能被重新分配；单 outstanding 适配器则可用一个寄存器完成整个 FSM。

#### 6.3 安全不变量

1. 每个 D response 都对应一个已经 fire 的 A request，且 `d_source` 与被接受请求匹配；没有未完成请求时不得返回 D。
2. A/D 的 payload 在 valid stall 期间稳定；`a_size`、地址对齐、`a_mask` 和 opcode 必须相容。
3. `PutPartialData` 的 mask 只能写指定 lane；未选 lane 不应产生副作用。
4. `d_denied` 与 `*_corrupt` 必须被上游观察、记录或转换；不能把 denied/corrupt 无条件改成成功数据。
5. TL-UL 不能承载多 beat burst；需要 burst、原子或一致性能力时必须升级协议或显式拆分/桥接。
6. source 表、FIFO 和复位逻辑要确保 D 不丢失、不会重复响应，且 source 复用发生在旧响应 fire 之后。

#### 6.4 常见桥接方式

- TL-UL ↔ AXI4/AXI4-Lite：将 `source` 与 AXI ID/队列项关联，映射 mask 与 `WSTRB`，把 `denied/corrupt` 转为 AXI `DECERR/SLVERR` 或保留在 user 状态；AXI burst 通常拆成多个 UL 单 beat。
- TL-UL → APB/AHB/Wishbone/OBI：桥内限制为一个或有限个 outstanding，映射 A fire 到目标请求，目标完成后产生 D；`a_mask` 对应 `PSTRB`/`SEL`/`be`。
- TileLink 一致性网络 ↔ UL：必须由 TL-C/UH/一致性节点或适配器终止/降级一致性语义；不能只连 A、D 就声称支持 coherent TileLink。
- 在 OpenTitan、Rocket-Chip/Chipyard 等系统中，TL-UL/TL 网络及其 adapter 是集成层能力；具体安全扩展和信号不一定属于基础 TL-UL 规范。

#### 6.5 版本与来源

以下按 SiFive TileLink 1.8.1 描述；不同 Chisel/Rocket-Chip 版本可能对 bundle 展平、`sink`、安全扩展和 adapter 名称做工程化调整。

- SiFive，*TileLink Specification 1.8.1*（规范 PDF 镜像）：<https://starfivetech.com/uploads/tilelink_spec_1.8.1.pdf>；SiFive CDN 版本：<https://sifive.cdn.prismic.io/sifive/7bef6f5c-ed3a-4712-866a-1a2e0c6b7b13_tilelink_spec_1.8.1.pdf>；访问日期：2026-09-06。
- Chips Alliance，TileLink interconnect implementation：<https://github.com/chipsalliance/tilelink>；访问日期：2026-09-06。
- OpenTitan，TL-UL IP/interface 集成说明：<https://opentitan.org/book/hw/ip/tlul/index.html>；访问日期：2026-09-06。

### 7. OBI

#### 7.1 信号

OBI（Open Bus Interface）是点到点的 Manager/Subordinate 接口。OBI 1.6 的最小核心语义可按 A（address/request）和 R（response）理解；典型信号包括：

- A 通道：`req`、`gnt`、`addr`、`we`、`be`、`wdata`。
- R 通道：`rvalid`、`rdata`、`err`。
- 可选/版本或 profile 相关 sideband：`aid`/`rid`、`atop`、`memtype`、`prot`、`dbg`、`auser`、`ruser` 等。
- 全局：时钟/复位；具体 RTL 接口可能使用 `*_o`/`*_i` 展平命名。

这里必须区分“OBI 核心握手”与某一 SoC 的完整 OBI profile。地址/数据宽度、是否支持原子操作、ID/outstanding、user/integrity 字段和 response 延迟都需从所用 OBI 版本及实现文档确认。

#### 7.2 事务状态机和时序

```text
IDLE --req=1--> A_WAIT
 A_WAIT: 保持地址/控制/写数据，直到 req && gnt
       --gnt--> R_WAIT（或按实现允许继续发出下一请求）
 R_WAIT: 等待 rvalid，采样 rdata/err/ruser
       --rvalid--> IDLE/下一个可接受请求
```

`gnt` 可以与 `req` 同周期返回，也可以延迟；在 `req=1 && gnt=0` 时，Manager 保持 A payload。A 被授权后，Subordinate 在规定的 response 时机用 `rvalid` 给出读数据或错误。基础 OBI 常见接口没有 AXI R 通道的 `rready`，所以不能机械地把 `rvalid` 当成可反压的 AXI response；适配器必须按 OBI profile 保证消费方可在 `rvalid` 时采样，并限制未完成请求数量。连续请求、同周期授权/返回和 response 是否为脉冲，均需与具体版本一致。

#### 7.3 安全不变量

1. `req && !gnt` 期间 `addr`、`we`、`be`、`wdata`、`atop` 和已实现的 sideband 稳定。
2. 一个 R response 只能对应已被 `gnt` 接受的 A request；有 ID 时必须按 ID 对应，没 ID 时必须按实现规定限制 outstanding。
3. `rvalid` 时 `rdata`/`err`/`ruser` 的语义有效；错误必须可到达上游，不能把 `err` 静默转换成成功。
4. `be` 的 lane 语义和地址对齐在桥接前后保持一致；原子/调试/特权属性不支持时要拒绝或显式降级。
5. 由于可能没有 response backpressure，接收方不能在未准备好时发起会导致无法消费的并发请求；复位要清除所有 outstanding bookkeeping。

#### 7.4 常见桥接方式

- OBI → AXI4-Lite：把 `req/gnt` 映射为 AW/W 或 AR 的 fire，使用一个 outstanding 寄存器等待 B/R，再把 AXI 响应变成 OBI `rvalid/rdata/err`。
- OBI → APB/AHB-Lite/Wishbone/Avalon-MM：以单次事务 FSM 映射 `be` 到 `PSTRB`、AHB byte lane、Wishbone `SEL` 或 Avalon `byteenable`；把目标协议 wait/error 变成 `gnt` 延迟和 R error。
- OBI ↔ TileLink-UL：用 source 表实现并发请求；没有 OBI ID 时收敛到单 outstanding，TL `denied/corrupt` 映射为 `err` 或 user 状态。
- OBI 的 `atop`、integrity、debug 和 security sideband 若目标总线没有等价字段，必须由桥接器、检查点或系统策略处理，不能因信号宽度不匹配直接丢弃。

#### 7.5 版本与来源

OBI 的历史说明明确提到它起源于 RI5CY/Ibex 一类的 custom interface；这说明接口形态有关联，但不等于当前 Ibex 的端口自动通过 OBI 1.6 合规认证。本文以 OpenHW Group OBI 1.6.0 为版本锚点。

- OpenHW Group，*OBI specification v1.6.0*：<https://github.com/openhwgroup/obi/blob/main/OBI-v1.6.0.pdf>；原始 PDF：<https://raw.githubusercontent.com/openhwgroup/obi/main/OBI-v1.6.0.pdf>；访问日期：2026-09-06。
- OpenHW Group，历史 OBI v1.2（说明其与 RI5CY/Ibex custom interface 的关系）：<https://raw.githubusercontent.com/openhwgroup/obi/188c87089975a59c56338949f5c187c1f8841332/OBI-v1.2.pdf>；访问日期：2026-09-06。

### 8. Wishbone Classic

#### 8.1 信号

- 系统：`CLK_I`、`RST_I`。
- 主设备输出：`ADR_O`、`DAT_O`、`WE_O`、`SEL_O`、`CYC_O`、`STB_O`；可选 `TGA_O`、`TGD_O`、`TGC_O`、`CTI_O`、`BTE_O`。
- 从设备返回：`DAT_I`、`ACK_I`、`ERR_I`、`RTY_I`（在从设备命名方向下常写作 `DAT_O/ACK_O/ERR_O/RTY_O`）。

实际端口方向由 master/slave 视角决定，集成时以接口方向而不是 `_I/_O` 的局部命名为准。`SEL` 选择数据总线的 byte lane；`CTI/BTE` 是 B4 的 cycle/burst 属性，Classic 单次访问可以不实现。

#### 8.2 事务状态机和握手

```text
CYCLE_IDLE --CYC=1--> CYCLE_ACTIVE
       CYCLE_ACTIVE --STB=1--> XFER_WAIT
       XFER_WAIT: 保持地址/数据/控制，等待 ACK/ERR/RTY
       ACK/ERR/RTY --> 撤销 STB；结束时撤销 CYC 或开始下一 STB
```

主设备用 `CYC` 声明总线周期，用 `STB` 声明当前有效传输；从设备在 `CYC && STB` 有效时可等待若干周期，然后以 `ACK`、`ERR` 或 `RTY` 之一终止。主设备必须保持 `STB` 和请求 payload，直到收到终止信号。连续 block cycle 可以保持 `CYC`，Classic 的普通单次访问则在 ACK 后结束该次 `STB`。

#### 8.3 安全不变量

1. `ACK/ERR/RTY` 只能在 `CYC && STB` 有效时终止一次请求；无请求时从设备不得响应。
2. `ACK`、`ERR`、`RTY` 必须互斥；主设备看到任一终止后撤销当前 `STB`，不能重复计数。
3. 等待期间 `ADR_O`、`DAT_O`、`WE_O`、`SEL_O`、tag 和 burst 属性稳定；`CYC` 覆盖整个 cycle。
4. `SEL` 的 byte lane 语义在读写和桥接中保持一致；不支持 `RTY` 时必须由系统禁止或定义为错误/重试策略。
5. 复位时 master 不得主动产生 `CYC/STB`；slave 的终止信号不能越过复位边界形成伪完成。

#### 8.4 常见桥接方式

- Wishbone Classic → APB/AHB/AXI4-Lite：用单 outstanding FSM，将 `CYC && STB` 转为目标请求，等待目标完成后返回 `ACK` 或 `ERR`；`RTY` 要么保留成重试，要么按系统规则转错。
- AXI4-Lite/TL-UL/OBI → Wishbone：把源协议的单次 fire 变成 `CYC/STB`，等待 ACK/ERR/RTY；有并发源协议时用队列或显式串行化。
- Wishbone ↔ Avalon-MM：`STB`/`ACK` 对应 Avalon 的 request/`waitrequest`，读数据用固定延迟或 `readdatavalid` 适配；要核对 Avalon 的 word address。
- B4 block/pipelined cycle → 单次目标总线：拆成普通 Classic 传输并保留 CTI/BTE 的结束/顺序语义。

#### 8.5 版本与来源

本文所称 Wishbone Classic 以 OpenCores 发布的 B4 规范为锚点；B3 文档和不同 FPGA vendor wrapper 可能采用不同 reset、tag 或 retry 约定。B4 的 Classic、block 和 pipelined 不是可以互换的同一实现。

- OpenCores，*Wishbone System-on-Chip (SoC) Interconnection Architecture for Portable IP Cores, Revision B4*：<https://cdn.opencores.org/downloads/wbspec_b4.pdf>；访问日期：2026-09-06。
- FOSSi/社区维护的 Classic 时序说明（用于交叉核对术语）：<https://wishbone-interconnect.readthedocs.io/en/latest/03_classic.html>；访问日期：2026-09-06。

### 9. Avalon-MM

#### 9.1 信号和接口属性

Avalon-MM 是 Intel FPGA 生态中的可配置 memory-mapped host/agent 接口，而不是一组每个实现都必须具备的固定端口。常见信号如下：

- 时钟/复位：`clk`、`reset`，以及某些 profile 的 `reset_req`、`clken`。
- Host → Agent：`address`、`read`、`write`（早期或封装可能使用 `read_n/write_n`）、`writedata`、`byteenable`、可选 `burstcount`、`beginbursttransfer`、`chipselect`。
- Agent → Host：`readdata`、`waitrequest`、可选 `readdatavalid`、`response`、`writeresponsevalid`、`writeresponse`、`readyfordata/dataavailable`。

端口是否存在由 interface properties（读延迟、是否可等待、是否支持 burst、响应类型等）决定。Intel 规范中的 Avalon-MM `address` 通常是 word address；与 byte-addressed 总线桥接时必须进行明确换算，不能仅连接低位地址。

#### 9.2 事务状态机和时序

```text
IDLE --read/write 请求--> ISSUE
ISSUE --waitrequest=1--> WAIT_REQUEST（保持请求 payload）
ISSUE --waitrequest=0--> WRITE_DONE 或 READ_WAIT_DATA
READ_WAIT_DATA --readdatavalid--> READ_DONE
WRITE_DONE --writeresponsevalid（若启用）--> IDLE
```

对于非流水写，请求在 `waitrequest=0` 时被 agent 接受；对于读，agent 可以在固定 latency 后给 `readdata`，也可以通过 `readdatavalid` 指示可变延迟/流水读数据。`waitrequest=1` 时 host 必须保持地址、读写控制、写数据、`byteenable` 和 burst 属性。burst 是否允许、每拍地址如何推进和读数据返回顺序，均由 profile/property 共同决定。

#### 9.3 安全不变量

1. `waitrequest` 未解除前，host 不改变当前请求的地址、方向、写数据、byteenable、burstcount 或相关控制。
2. `readdatavalid` 只能对应一个已接受的读请求；同周期 `readdata` 和响应字段必须有效，且遵守 profile 的 latency/ordering。
3. `byteenable` 未选中的 lane 不得修改；word address 与总线 byte address 的转换要经过统一的地址单元规则。
4. agent 不应驱动其未声明的 response/flow-control 信号；host 不能把缺失的 `readdatavalid` 当成任意延迟读。
5. reset 期间不能接受新事务；若 profile 有 outstanding/read-pipeline，复位必须清除其计数和返回队列。
6. Avalon-MM 没有一个跨所有 profile 统一的安全属性字段；地址权限、特权和非安全标记必须由 adapter/interconnect 额外承载或在边界拒绝。

#### 9.4 常见桥接方式

- Intel Platform Designer/Interconnect：根据 host/agent interface properties 自动插入互连、宽度转换、时钟/复位和适配器；这是 Intel 集成工具能力，不代表任意 Avalon-MM 实现都拥有同样的转换。
- Avalon-MM ↔ AXI4-Lite/APB/AHB/Wishbone/OBI：将 `waitrequest` 映射为目标总线的 ready/等待，将 `readdatavalid`/writeresponse 映射为读/写响应；保留 byteenable、错误和地址单位。
- Avalon burst → APB/OBI/Wishbone Classic：拆成单次传输并缓存 burst context；反向连接时只有目标协议真正支持 burst 才能合并，否则必须逐 beat 返回。

#### 9.5 版本与来源

Intel Avalon-MM 的信号命名和属性随规范版本、Quartus/Platform Designer 版本及 IP profile 变化。使用 vendor IP 时，应把生成的 `.tcl`/interface metadata 与 RTL port list 一起作为事实来源。

- Intel，*Avalon Interface Specifications*（官方文档页）：<https://www.intel.com/content/www/us/en/content-details/655048/avalon-interface-specifications.html>；规范 PDF（1.3 版）：<https://cdrdv2-public.intel.com/655048/mnl_avalon_spec_1_3.pdf>；访问日期：2026-09-06。
- Intel，*Avalon Interface Specifications*（较新发布 PDF）：<https://cdrdv2-public.intel.com/667068/mnl_avalon_spec-683091-667068.pdf>；访问日期：2026-09-06。
- Intel，Avalon-MM signals（当前在线手册页面）：<https://www.intel.com/content/www/us/en/docs/programmable/683130/25-3/avalon-memory-mapped-interface-signals.html>；访问日期：2026-09-06。

### 10. AXI4-Stream（补充）

#### 10.1 信号、状态和时序

AXI4-Stream 没有地址通道，常见信号是 `TVALID`、`TREADY`、`TDATA`、`TLAST`，以及可选的 `TKEEP`、`TSTRB`、`TID`、`TDEST`、`TUSER`。每一个 `TVALID && TREADY` 上升沿传输一个 beat；发送端在 `TVALID=1 && TREADY=0` 时保持 `TDATA` 和所有相关 sideband，`TLAST` 在包的最后一个 beat 标记边界。其状态机是流量产生/等待 ready/包结束，不包含 memory-mapped 的地址译码或响应码。

#### 10.2 安全不变量与桥接

- `TLAST`、`TKEEP`、`TUSER` 与对应数据 beat 必须稳定且不能错位；背压时不得跳过或重复 beat。
- 由于没有内建地址权限和完成错误语义，Stream → AXI4/APB 等桥接需要 DMA/FIFO/描述符、地址分配和错误通道；AXI memory-mapped burst 也不能仅靠 `TLAST` 自动重建。

- Arm，*AMBA 4 AXI4-Stream Protocol Specification*，IHI 0051：<https://developer.arm.com/documentation/ihi0051/latest/>；访问日期：2026-09-06。

### 11. 跨协议桥接的共同检查清单

实现任何组合器或 adapter 时，至少应检查以下语义，而不只是检查端口是否连线：

| 检查项 | 必须保持的语义 | 典型失败后果 |
|---|---|---|
| 地址单位/对齐 | byte address、word address、beat size 和 lane mask 一致 | 访问相邻寄存器、越界写、错误 burst |
| 接受与完成 | 源请求只在目标真正接受后释放；响应只在目标完成后生成 | 丢请求、重复请求、提前响应 |
| 背压稳定性 | `VALID&&!READY`、`PREADY=0`、`HREADY=0`、`waitrequest=1`、`STB&&!ACK` 时保持 payload | 同一事务字段漂移 |
| 并发/顺序 | ID/source 与队列一一对应；不支持并发则反压/串行化 | 响应配错 master 或事务 |
| byte enable | `WSTRB/PSTRB/SEL/be/byteenable/a_mask` lane 语义可逆 | 未选字节被覆盖 |
| 错误/拒绝/损坏 | `PSLVERR/HRESP/BRESP/RRESP/ERR/denied/corrupt` 可观察并按策略转换 | 安全或完整性错误被伪装为成功 |
| 属性 | `PPROT/AxPROT/HPROT/HNONSEC/OBI prot` 等保留或显式拒绝 | 权限边界丢失 |
| 复位/超时 | 清空 outstanding、禁止伪造完成；超时策略明确 | 长时间测试中死锁或状态污染 |
| 不支持能力 | burst、atomic、coherence、retry、可变读延迟不得静默假支持 | 难以复现的协议违规 |

## 参考文档二：Ibex、CVA6、BOOM 接口边界矩阵

### 12. 术语和判定口径

- “核心原生接口”指 standalone core 或 core top 在不依赖 SoC generator/外部 wrapper 时公开的 memory/fetch 合约；核心内部的私有 cache、前端或流水线接口不自动算作标准总线。
- “SoC 集成接口”指官方示例、wrapper、uncore 或 SoC generator 为该核提供的外部连接方式；它可以是标准总线，但仍不等于 standalone core 原生实现了所有该总线变体。
- “需要桥接”表示目标协议和该核的对外合约在信号/状态/并发/属性上不能安全直连；即使已有开源 adapter，也应验证具体版本和参数。

### 13. 总矩阵

| 核 | 核心原生接口（不泛化） | SoC 集成接口（资料明确的范围） | 对 APB4/AXI4-Lite/AXI4/AHB-Lite/TL-UL/OBI/Wishbone/Avalon-MM 的桥接判断 |
|---|---|---|---|
| **Ibex** | 指令和 LSU 都是 custom request/grant/response：`instr_req_o/instr_gnt_i/instr_rvalid_i`、`data_req_o/data_gnt_i/data_rvalid_i`，并带地址、读写、byte enable、写/读数据和错误；SecureIbex 可增加 integrity。官方端口没有把它命名为 AXI 或 OBI。 | `examples/simple_system` 直接把 Ibex、统一指令/数据存储器、timer/peripheral 和简单地址译码组合起来；实际 SoC 可在 wrapper 中接 OBI、TL、AXI、APB 等。 | 八种协议都应视为需要 adapter/SoC wrapper。OBI 在握手形态上最接近，且 OBI 历史文档提到起点与 Ibex custom interface 有关，但不能因此宣称当前 Ibex 端口已经是 OBI 1.6；仍需核对 integrity、sideband、response 语义。AXI/AHB/TL/WB/Avalon/APB 不能直连。 |
| **CVA6** | 具体配置下的对外 memory interface：常规缓存配置为 AXI4 memory interface；官方文档还描述受限 AXI5 Atomic Operations。`PipelineOnly`/CV32A60X 配置提供 OBI 1.6 风格的 fetch/load/store 接口。内部 cache/MMU 信号不是公共总线。 | CVA6 wrapper/SoC 可将 AXI4 manager 接到 memory/peripheral fabric；CV32A60X 文档明确列出三个 OBI 接口。是否使用 AXI 或 OBI 由配置、产品和版本决定。 | AXI4 仅在相应配置的外部接口上可直接集成，不能推广为全部 CVA6/AXI5 能力；AXI4-Lite、APB、AHB、TL-UL、WB、Avalon 需 adapter。OBI 仅在 `PipelineOnly`/CV32A60X 类配置按 OBI 1.6 处理；普通缓存配置仍需 AXI↔OBI 或目标总线桥。 |
| **BOOM** | standalone BOOM 的公开核心连接主要是 Chisel/Rocket Chip 内部的 frontend、`HellaCacheIO`/cache shim 等合约；这些是版本敏感的内部接口，不是 standalone BOOM 的 APB/AXI/TL/WB/OBI/Avalon 端口。 | 官方 BOOM 说明要求通过 Chipyard/Rocket Chip 组成可运行 SoC；Chipyard 的 system bus 是 TileLink 网络，外部/DRAM 侧常通过 TileLink-to-AXI 连接 AXI4-compatible controller。 | 不能把“BOOM 在 Chipyard 使用 TileLink/AXI”写成 BOOM 核心原生支持 TL/AXI。脱离 Chipyard 时，八种协议都需要自定义 tile/uncore wrapper 或相应 adapter；接 APB/AHB/WB/Avalon/OBI 通常先接入 TL/AXI fabric，再由 fabric bridge 转换。 |

### 14. Ibex

#### 14.1 原生边界

Ibex 的 instruction fetch 端口以请求保持、grant 接受和单周期 `instr_rvalid_i` 返回为核心：`instr_req_o` 在未获 `instr_gnt_i` 前保持，地址要求按指令对齐；返回包含 `instr_rdata_i` 和 `instr_err_i`。LSU 对数据访问采用类似的 `data_req_o/data_gnt_i/data_rvalid_i`，并显式给出 `data_addr_o`、`data_we_o`、`data_be_o`、`data_wdata_o`、`data_rdata_i`、`data_err_i`。这些语义适合映射为 OBI-like 请求/授权/响应，但官方 Ibex integration 文档的命名和合约不能被改写成“原生 AXI”或“已认证 OBI”。SecureIbex 的数据/指令完整性信号还会使简单 adapter 不足。

#### 14.2 SoC 集成与桥接

官方 `simple_system` 是可运行示例：Ibex core、统一 instruction/data memory、timer 和 peripheral 通过简单系统级连接组合；它证明的是该示例的集成结构，而非 Ibex 内核内置 APB/AXI/TL 控制器。若把 Ibex 接到协议组合器，建议先建立一个明确的 Ibex request adapter：

1. 在 `req && !gnt` 期间锁存并保持地址、方向、byte enable、写数据及完整性/安全属性。
2. 目标总线真正接受后才返回 `gnt`；目标读/写完成时产生恰好一次 `rvalid`，并把错误转换为 `data_err_i/instr_err_i`。
3. 目标总线支持并发或多拍时，默认收敛为单 outstanding；除非额外设计事务表，否则不得让 response 超过 Ibex 端口能区分的数量。

官方来源（访问日期均为 2026-09-06）：

- Ibex integration ports and system integration：<https://ibex-core.readthedocs.io/en/latest/02_user/integration.html>；GitHub 原文：<https://github.com/lowRISC/ibex/blob/master/doc/02_user/integration.rst>。
- Ibex instruction fetch protocol：<https://ibex-core.readthedocs.io/en/latest/03_reference/instruction_fetch.html>。
- Ibex load/store unit protocol：<https://ibex-core.readthedocs.io/en/latest/03_reference/load_store_unit.html>。
- Ibex simple system：<https://github.com/lowRISC/ibex/blob/master/examples/simple_system/README.md>。

### 15. CVA6

#### 15.1 配置相关的原生/对外接口

CVA6 官方用户手册把 memory interface 描述为 AXI4，并说明某些 CV32A60AX/CV32A60X 变体还实现受限的 AXI5 Atomic Operations；这不等于实现全部 AXI5 optional features。官方参数文档同时说明 `PipelineOnly` 配置不使用 cache，并改用 OBI 而不是 AXI。CV32A60X 设计文档进一步明确三个 OBI 接口（fetch、load、store）符合 OBI 1.6。由此应使用如下判定：

- 普通缓存配置：把 CVA6 对外 memory port 当作其文档规定的 AXI4 profile，核对 ID、读写并行限制、`AxCACHE` 等具体实现约束。
- `PipelineOnly`/CV32A60X 配置：按该配置的 OBI 1.6 接口连接；不要把这一配置结论外推到所有 CVA6 构建。
- “CVA6 支持 AXI5”只在官方写明的 atomic/configuration 场景使用，并记录 AXI5 atomic 的限制；不能因此假定 AXI5-Lite、完整原子集或一致性协议均可用。

#### 15.2 SoC 集成与桥接

CVA6 的 AXI4 memory interface 可以直接接 AXI4-compatible memory/interconnect（在满足官方限制时）；接 APB/AHB/TL-UL/Wishbone/Avalon-MM 需要桥。若选用 OBI 配置，则需要 OBI fabric 或 OBI-to-target adapter。AXI4 ↔ AXI4-Lite 也不能只删除 ID/信号：必须处理 burst、并发、错误和保护属性；必要时将访问限制成单拍并反压。

官方来源（访问日期均为 2026-09-06）：

- CVA6 AXI interface：<https://docs.openhwgroup.org/projects/cva6-user-manual/01_cva6_user/AXI_Interface.html>。
- CVA6 requirements（AXI4/AXI5 atomic 的范围）：<https://docs.openhwgroup.org/projects/cva6-user-manual/02_cva6_requirements/cva6_requirements_specification.html>。
- CVA6 parameters/configuration（`PipelineOnly` 与 OBI）：<https://docs.openhwgroup.org/projects/cva6-user-manual/01_cva6_user/Parameters_Configuration.html>。
- CV32A60X design（三个 OBI 1.6 接口）：<https://docs.openhwgroup.org/projects/cva6-user-manual/07_cv32a60x/design/design.html>。

### 16. BOOM

#### 16.1 核心原生边界

BOOM 是 Chisel/Rocket Chip 生态中的可参数化 RV64GC out-of-order core。官方仓库明确提示 standalone BOOM 不是自运行 SoC，需要通过 Chipyard 等系统生成器实例化。BOOM 的 frontend、instruction cache、data cache shim 和 `HellaCacheIO` 等接口是核与 cache/uncore 之间的内部工程合约；它们会随 BOOM/Rocket Chip 版本变化，不能从名称推断为 AXI、TileLink 或 OBI 的公共端口。

BOOM memory-system 文档描述其使用 Rocket Chip 的 non-blocking cache，BOOM 与 data cache 之间有 shim 跟踪 inflight loads，并依赖 coherent cache 系统。这表明标准 memory-mapped 总线通常位于 cache/uncore 外侧，而不是 BOOM pipeline 的直接输出。该文档还标注自身可能过时，因此本段只用于确定架构边界，不能替代当前生成配置的 RTL/接口 metadata。

#### 16.2 SoC 集成与桥接

在 Chipyard/Rocket Chip 集成中，system bus 是 TileLink 网络，连接 tile、L2 和 MMIO；外部内存控制器通常是 AXI4-compatible，并通过 TileLink-to-AXI adapter 接出。因此可以说“该 SoC 集成支持 TL/AXI”，但不能说“standalone BOOM 原生支持 TL/AXI”。将外设接到 APB4、AHB-Lite、AXI4-Lite、Wishbone、Avalon-MM 或 OBI 时，通常选择：

1. 先接入 Chipyard/Rocket Chip 的 TL/AXI fabric，再使用对应的官方/生态 adapter；或
2. 编写 custom tile/uncore wrapper，把 BOOM cache/TileLink 边界转换为目标协议，并验证一致性、缓存属性、错误和地址窗口。

没有 Chipyard/Rocket Chip 这层时，不能只给 BOOM core 连接一个 APB/AXI slave 端口来完成系统集成。

官方来源（访问日期均为 2026-09-06）：

- BOOM 官方仓库及 standalone/Chipyard 说明：<https://github.com/riscv-boom/riscv-boom>。
- BOOM instruction fetch stage（内部 frontend/i-cache 边界）：<https://github.com/riscv-boom/riscv-boom/blob/master/docs/sections/instruction-fetch-stage.rst>。
- BOOM memory system（cache shim、coherence；文档注明可能过时）：<https://github.com/riscv-boom/riscv-boom/blob/master/docs/sections/memory-system.rst>。
- Chipyard memory hierarchy（TileLink system bus、AXI-compatible outer memory）：<https://github.com/ucb-bar/chipyard/blob/main/docs/Customization/Memory-Hierarchy.rst>；在线文档入口：<https://chipyard.readthedocs.io/en/latest/>。

### 17. 面向协议组合器的结论

1. **Ibex** 最适合先用一个低资源、单 outstanding 的 OBI-like adapter 接入组合器，再在边界处转换为 APB4、AXI4-Lite 或 TL-UL；这是一种实现策略，不是把 Ibex 端口重新命名为标准协议。
2. **CVA6** 必须把配置作为 manifest/测试输入的一部分：普通缓存路径验证 AXI4 profile，`PipelineOnly`/CV32A60X 路径验证 OBI 1.6；同一“CVA6 支持协议”标签不足以选择桥。
3. **BOOM** 应把 TileLink/AXI 视为 Chipyard/Rocket Chip 集成层边界；长时间测试中要锁定 generator、adapter、TL/AXI 参数和内存模型版本，避免把系统级能力归因于 core。
4. 协议组合生成器的 fail-closed 条件至少应包括：协议/profile 缺失、版本不匹配、源/目标地址单位不明、目标不支持 burst/atomic/coherence、source/ID 深度不足、错误/安全属性没有映射，以及生成的 wrapper/source list 不是从固定输出目录可复现消费的绝对路径。
5. 长时间测试应分别覆盖：无等待、随机等待、持续背压、读写交错、byte lane、错误/deny/corrupt、复位中止、最大 outstanding、burst 边界和地址区域权限；仅有“能生成 Verilog”不能证明桥接正确。

## 18. 参考资料索引（官方/一手来源）

| 主题 | 来源 | 访问日期 |
|---|---|---|
| APB4/APB | Arm IHI 0024 | 2026-09-06 |
| AXI4/AXI4-Lite | Arm IHI 0022 | 2026-09-06 |
| AHB-Lite | Arm IHI 0033 | 2026-09-06 |
| TileLink-UL | SiFive TileLink 1.8.1 | 2026-09-06 |
| OBI | OpenHW Group OBI 1.6.0 | 2026-09-06 |
| Wishbone Classic | OpenCores Wishbone B4 | 2026-09-06 |
| Avalon-MM | Intel Avalon Interface Specifications | 2026-09-06 |
| AXI4-Stream | Arm IHI 0051 | 2026-09-06 |
| Ibex | lowRISC Ibex documentation | 2026-09-06 |
| CVA6 | OpenHW CVA6 User Manual | 2026-09-06 |
| BOOM/Chipyard | riscv-boom、Chipyard 官方仓库/文档 | 2026-09-06 |

本文中的 URL 已在各协议/核章节逐项展开；索引只用于快速定位，不替代具体版本文档。
