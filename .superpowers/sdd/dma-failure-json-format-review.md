# DMA failure JSON 格式修复独立复核

只读复核当前唯一runtime改动 `requested_source_bytes=values`→`list(values)`、新增failure-document软件测试和已有RED/GREEN日志；没有运行测试、native、远端或修改实现。

**结论：无高/中问题，最小修复合理。** values仍由有界1..16整数byte输入收集并校验，list只是把原有byte序列转为JSON array对应的Python wire type，不改值、顺序或数量。它在构造原始failure diagnostic时执行，使原始error与JSON roundtrip后的error类型一致；不是在replay比较时容忍tuple/list差异，也没有删除严格相等断言。

message/type、command_count、case_start、phase/case_index、source/case bounds、ResourceBudget、source pins、原始commands/events及native uncertainty/finalize比较逻辑完全未改。replay仍要求异常类型/消息/命令边界相同并比较完整finalized prefix；该修复不会把一次不同失败变成相同。

新增测试实际调用run_continuous_uart_rx的catch/diagnostic builder，只替换recorder和capture产生早期无transport失败，检查原始message、requested_source_bytes=[0x33]和整个error的JSON往返严格相等。未用预制error对象替代被测builder。已有RED1failed/0.31s与GREEN6passed1skipped/0.34s日志内容相符；本轮未重复执行，native skip不计pass。

本场景diagnostic其他字段均为string/int/list，Error本身无其他tuple成员，未发现需要扩大修改范围。其他bundle字段可有其各自的JSON转换合同，不应借此改宽整体比较policy。

当前runtime SHA：`ac42397cec75b177eb40e76ba2186776736c4b28376dd9cb39c72cc62e731dba`；新test SHA：`4800016c35185b9d96e82e3bace4e044fdfa3e32a31f42066abb9797fbe8eba1`。

Attempt5真实native exit1应保留；原始四阶段结果和内部replay成功不替代最后严格assert。当前只修JSON宿主类型一致性，未取得新native gate通过；attempt6完整重跑仍待授权窗口，不从此软件修复授continuous/native/P7结果。
