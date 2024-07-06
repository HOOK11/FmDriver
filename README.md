# FM驱动
      ps:某个盆友驱动(一年前) 花了点时间修改了下 都是CV的 疯狂的抄
# 驱动功能
      1.驱动读写 使用 `MmCopyVirtualMemory读取伪造的进程对象作为目标进程 写入使用MmCopyVirtualMemory 失败 则改为Mdl写入
      2.驱动注入 线程注入（伪装隐藏线程）并清空线程回调通知  （ps:如果不禁用 PUBG 会出现内存异常）buid 自行杀毒 加密 解密 dll字节
            如何处理内存 以及申请内存 不建议使用Zw 以及Mdl 申请内存  不建议使用线程注入
            测试游戏PUBG 
      3.通讯 修改  获取 \\Device\\Null `Null.sys驱动的 FastIoDispatch` 表  `FastIoDeviceControl` 成员修改为 `DeviceIoControl`
            当有快速I/O设备控制操作被请求时，`DeviceIoControl` 函数将被调用
      4.获取模块
      5.伪装进程
      6.查询内存
 # PUBG注入演示
https://caiba123.oss-cn-beijing.aliyuncs.com/bandicam%202024-02-17%2018-35-41-357.mp4

![image](https://github.com/HOOK11/FmDriver/blob/master/QQ%E6%88%AA%E5%9B%BE20230724213321.png)


# 建议参考
      1.驱动读写CV https://github.com/rogxo/ReadPhys
      2.部分函数特征码 NtQueryVirtualMemory NtProtectVirtualMemory 等等 如出现不兼容情况 参考 https://github.com/Oxygen1a1/oxgenPdb项目

开发Tps游戏 缺地编  来个大手子 一起合作开发游戏 有意向可以加我  目前8人（学生狗）

如果对你有帮助的话，希望可以点一下star呀

