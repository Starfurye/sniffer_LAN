# 简易局域网端口嗅探器

该嗅探器只能在Linux平台上使用，不要尝试在Windows和WSL上使用，WSL无法操作物理网卡。同样不建议在其他Unix发行版上使用。


# 运行

1. 使用makefile编译

```bash
$ make
```

2. 清理

```bash
$ make clean
```

## 用法


启动嗅探器：

```bash
$ sudo ./sniffer
```

输入网卡名称，该网卡将被设置为混杂模式。

```bash
Interface name:[Interface name]
Interface name:wlan0
```

用`control-C`终止嗅探，网络包解析结果保存在`log.txt`中。
