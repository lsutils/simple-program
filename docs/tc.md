- 分类器比 XDP 更老，它从内核 4.1 开始可用，而 XDP 从 4.8 开始可用。
- 分类器可以检查入口和出口流量。 XDP 仅限于入口
- XDP 提供了更好的性能，因为它执行得更早 - 它从 NIC 驱动程序接收原始数据包，然后再进入内核网络堆栈的任何层并解析为 sk_buff 结构。

- TC_ACT_OK
- TC_ACT_RECLASSIFY
- TC_ACT_SHOT
- TC_ACT_PIPE
- TC_ACT_STOLEN
- TC_ACT_QUEUED
- TC_ACT_REPEAT
- TC_ACT_REDIRECT
- TC_ACT_TRAP
- TC_ACT_VALUE_MAX
- TC_ACT_EXT_VAL_MASK
                        

## Cgroup SKB 和分类器都接收相同类型的上下文 - SkBuffContext。