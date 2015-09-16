		           apsta使用指导


sta连接ap以后以中继的方式延展ap网络，可以增加ap的无线覆盖范围，能以较低的成本大大的提升无线网络覆盖率和使用便捷性。



一.功能特性
1.apsta支持open、wep、wpa/wpa2加密；
2.apsta建立的软ap名称(SSID)可以自由配置；
3.apsta建立的软ap最多支持8个sta加入；
4.apsta模式下socket通信最大传输速率达到3Mbit/s;
5.支持apsta级联通信；




二.如何编译
1.在wm_config.h中打开TLS_CONFIG_AP和TLS_CONFIG_APSTA的宏定义，然后编译出的就是带有apsta功能的版本。
2.在wm_wifi_oneshot.h中将宏CONFIG_NORMAL_MODE_ONESHOT定义为0，然后编译出的就是带有apsta一键配置功能的版本。



三.可配选项
1.配置napt表项的超时时间。
  在alg.h头文件中，通过NAPT_TABLE_TIMEOUT配置，单位为秒，默认为60s；
  该时间定义太短可能导致及早删除表项无法收到从上层路由回来的报文，
  定义太长可能导致导致内存耗尽后续通信无端口可用，所以需要合理选择该时间：
  做路由器上网应该缩短该时间并增加表项条数(条数修改见下)；
  做通信应该根据实际情况延迟该时间并应该采用心跳包机制维持连接不断。

2.配置是否限制napt表项大小。
  因为表项每条记录都需要一定内存空间，大量的表项记录会导致内存资源耗尽，
  所以可以使用该选项限制napt表项占用的内存空间，tcp/udp每条记录是12个字节，icmg每条记录是8个字节。
  在alg.h头文件中，定义宏NAPT_TABLE_LIMIT则开启napt限制，未定义则不开启napt限制，默认为开启限制；
  宏NAPT_TABLE_SIZE_MAX定义了napt的大小，默认为1000(1000条napt表项记录大约12k)，
  表项太少可能会导致部分应用没有端口而无法通信。
  如果想增大表项条数，还应该修改增大start.s中堆的大小(如条数从1000—>1500，堆配置为0x00010000—>0x00012000)。

3.可指定napt表项端口起始位置(序号)。
  在alg.h头文件中，NAPT_LOCAL_PORT_RANGE_START和NAPT_LOCAL_PORT_RANGE_END指定了napt表可分配的起始端口号，
  napt表限制大小必须在该范围内，默认为15000~19999；
  在该范围内的端口，如果已被napt使用，在上层应用中绑定该端口会提示端口已被占用；如果已被上层应用使用，napt不会抢占该端口，会继续寻找其它可用端口来使用。

4.可动态查看napt表使用情况。这个仅仅提供给调试使用，在alg.c中定义宏NAPT_ALLOC_DEBUG，则会串口打印出napt表项的分配和释放轨迹，默认不开启此功能。



四.操作方式
1.使用一键配置，需要编译为apsta一键配置版本；
2.代码调用api接口："tls_wifi_apsta_start"或"tls_wifi_apsta_start_by_bssid"；
3.AT指令："AT+WPRT=3"设置apsta模式，"AT+SSID2=wifi_ssid"设置软ap网络名称，其余操作同sta模式；
4.Demo演示时串口发送"t_apsta";

