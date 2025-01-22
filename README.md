## fastdrop

利用ebpf 开发的快速丢包工具， 快速丢弃指定ip请求的包，减少协议栈的计算开销，减少CPU+网卡的负载。

loader 是使用 go +  github.com/cilium/ebpf 开发而成， 从redis 读取 ip(source ip) + port(dest port), 

将ip + port 加入到ebpf map中，拦截指定ip到本机端口的包，不区分tcp/udp， 当port 为0时，拦截所有的包。


使用场景： 抗D 、 WAF、 网关、 CDN， 等等



ubuntu 24.04 下编译：

    apt install  clang llvm git golang make gcc-multilib -y

    make

