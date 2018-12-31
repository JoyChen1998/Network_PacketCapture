# Network_PacketCapture
My computer-network project about packet capture. 

## 运行环境
+ Python 3.5 (or latest)        [ need module basically => `socket` ,  `struct` ]
+ OS Platform   =>   Linux
+ Note:  
    1. macOS 无法使用`socket`的关键字`socket.AF_PACKET` ，因此使用CentOS.
    2. Windows 我没有测试过，欢迎你的测试.
    3. 需要在root下运行.

## 功能点实现
+ 能够侦听到所有来自或从本机的MAC帧
+ 能够分析数据包和解包，基本按照协议头部来进行分析
+ 能够根据指定的来源和目的IP来过滤数据包。例子类似上一条
+ 能够保存收到的含各上层协议的数据包
+ 能够根据DF、MF等信息来重组完整TCP包
+ 能够根据指定的协议来过滤数据包。 例如，只侦听ICMP包，或者ICMP和TCP包等
    + 将HTTP协议的数据包内容另外存放
+ 查询功能（这个我认为从保存的文件中手工查询已经足够了hh）

## 配置说明
+ `INTERVAL`  [ int ]

    在方法`unpack_eth_packet`中，该变量控制每次获取MAC帧的速度，默认运行的时候取包间隔1s。
    
+ `HAVE_SAVED`  [ boolean ]

    该变量控制是否写入文件保存解得的数据包部分，默认为`False`(不保存)，在每一个解包方法中都有控制是否写入文件。
    
+ `HAVE_FILTER_PROTOCOL`  [ boolean ]

    该变量控制是否过滤某种协议，默认为`False`(不过滤)，在`unpack_ip_packet`中使用。开启过滤时，需要输入协议(upper case)，然后就只会解指定协议的数据包，不会尝试解别的协议的数据包。
    
+ `HAVE_FILTER_IP`  [ boolean ]

    该变量控制是否需要过滤`来源IP`和`目的IP`，默认为`False`(不过滤)，在`unpack_ip_packet`中使用。开启过滤时，需要输入指定的`来源IP`和`目的IP`。然后就只会解指定IP的数据包，不会尝试解含有别的IP的数据包。
    
+ 以上变量都在`CONFIG`中，要显示的字段，都在类的init方法中，以`字典`的形式形式存储，以`遍历`的方式输出(和保存)

## 运行流程
+ 显示网卡信息，我设置了只显示网卡和对应IP。（可以对不同的网卡进行选择，bind之后接收数据）

+ 根据配置中的变量情况确定是否进行相应的过滤操作。 

+ 尝试建立`socket`连接，若成功，则进行解析MAC帧；若失败，则结束该程序。
    + 首先获取MAC帧的首部的MAC来源和目的地址，并将其各个字段传入MAC字典保存，然后判断该MAC帧是否正常，若正常，则尝试解网络层协议数据包部分。

+ 开始解析网络层协议数据包部分，首先分析该IP数据包头部。
    + 获取其来源和目的IP、版本号、MF标志、DF标志、标识、上层数据包协议(根据协议号进行判断)、TTL值等，并将其各个字段传入IP字典保存。若开启过滤，此时就会进行对协议和IP的过滤操作。然后开始进行对`ICMP`协议和传输层协议的数据包的解析。

+ 开始解析传输层和ICMP协议数据包部分，首先分析该IP数据包的上层(ICMP属于本层)协议头部。
    + 此时，可以以相同的手法获取相应的`TCP`、`UDP`、`ICMP`首部对应的信息，对应的，剩下的数据部分就是数据段部分。
    + 同时，需要注意的是：尝试对数据段部分进行一次`utf-8`编码的转换（为了应用层HTTP协议等，查看请求数据，否则会出现文字段部分乱码的现象）.尝试失败就进行转16进制后转ascii码，然后将其传入对应协议的字典保存。
    + 此时，若捕捉到`HTTP`上层协议信息，则将该数据段另外保存。（可知为某些HTTP请求的信息，另外存放以便分析/搜索字段） -- added on 2018/12/28

+ 若开启文件保存，就在每个方法末尾加上文件写入，将获取的所有数据包信息保存到文件以便后面查看。

--- 

对此存在疑惑或者代码出现了问题？欢迎大佬提出issues指正。



    

