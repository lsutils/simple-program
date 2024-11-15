```
中断处理之后、网络堆栈本身所需的任何内存分配之前放置在 NIC 驱动程序中
```


- XDP_PASS：            让数据包继续通过网络堆栈
- XDP_DROP：            静默丢弃数据包
- XDP_ABORTED：         丢弃带有跟踪点异常的数据包
- XDP_TX：              将数据包弹回其到达的同一网卡
- XDP_REDIRECT：        通过 AF_XDP 地址族将数据包重定向到另一个 NIC 或用户空间套接字


# Generic XDP通用XDP
- XDP程序作为普通网络路径的一部分加载到内核中
- 不需要网卡驱动程序的支持即可运行
- 不提供完整的性能优势
- 测试 XDP 程序的简单方法

# Native XDP原生 XDP
- XDP 程序由网卡驱动程序加载，作为其初始接收路径的一部分
- 需要网卡驱动程序支持才能运行
- 默认操作模式

# Offloaded XDP卸载XDP
- XDP程序直接加载在网卡上，不使用CPU执行
- 需要网卡支持