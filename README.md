# Network_PacketCapture
My computer-network project about packet capture. 

## 运行环境
+ Python 3.5 (or latest)    
    [ need module basically => `socket` ,  `struct` ]
+ OS Platform
    Linux
    + note:  
        1. macOS 无法使用`socket`的关键字`socket.AF_PACKET` ，因此使用CentOS。Windows 我没有测试过，欢迎你的测试
        2. 需要在root下运行

## 功能配置说明
+ `INTERVAL`  [`int`]
    该变量控制每次获取MAC帧的速度，默认被注释，在方法`unpack_eth_packet`中
+ `HAVE_SAVED`  [`boolean`]
    该变量控制是否写入文件保存解得的数据包部分，默认为`False`(不保存)，在每一个解包方法中都有控制
+ `HAVE_FILTER_PROTOCOL`  [`boolean`]
    该变量控制是否过滤某种协议，默认为`False`(不过滤)，在`unpack_ip_packet`中使用。开启过滤时，需要输入协议(upper case)，然后就只会解指定协议的数据包，不会尝试解别的协议的数据包。
+ `HAVE_FILTER_IP`  [`boolean`]
    该变量控制是否需要过滤`来源IP`和`目的IP`，默认为`False`(不过滤)，在`unpack_ip_packet`中使用。开启过滤时，需要输入指定的`来源IP`和`目的IP`。然后就只会解指定IP的数据包，不会尝试解含有别的IP的数据包。
+ `HAVE_SEARCH`  [`boolean`]
    该变量控制是否查找数据包中的某个关键词部分，默认为`False`(不查找) (个人认为其实在保存文件之后，完全可以手动搜索hhh，这个功能不是很想做)
+ 以上变量都在`CONFIG`中，要显示的字段，都在类的init方法中，以`字典`的形式形式存储，以`遍历`的方式输出(和保存)

## 运行流程
+ 先根据配置中的变量情况确定是否进行相应的过滤操作。 
+ 尝试建立`socket`连接，若成功，则进行解析MAC帧；若失败，则结束该程序。首先获取MAC帧的首部的MAC来源和目的地址，并将其各个字段传入MAC字典保存，然后判断该MAC帧是否正常，若正常，则尝试解网络层协议数据包部分。
+ 开始解析网络层协议数据包部分，首先分析该IP数据包头部。获取其来源和目的IP，以及版本号，上层数据包协议(根据协议号进行判断)，TTL值等，并将其各个字段传入IP字典保存。若开启过滤，此时就会进行对协议和IP的过滤操作。然后开始进行对`ICMP`协议和传输层协议的数据包的解析。
+ 开始解析传输层和ICMP协议数据包部分，同样首先分析该IP数据包的头部。此时，可以以相同的手法获取相应的`TCP`、`UDP`、`ICMP`首部对应的信息，对应的，剩下的数据部分就是数据段部分。同时，需要注意的是：*数据段部分需要进行一次`utf-8`编码的转换，否则会出现文字段部分乱码的现象.* 然后将其传入对应协议的字典保存。
+ 若开启文件保存，就在每个方法末尾加上文件写入，将获取的所有数据包信息保存到文件以便后面查看。

--- 

对此存在疑惑或者代码出现了问题？欢迎大佬提出issues指正。



    

