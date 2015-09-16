DLNA编译操作：
1)解压DLNA压缩包到当前文件夹

2)执行DLNA批处理文件，当前工程的相应文件会被更新
tl6_sdk.sct
wifi.lib
wifi_costdown.lib
wm_config.h
wm_uart.h
wmdlna.lib

3)把wmdlna.lib添加到SDK工程

4)打开DEMO开关：\App\demo\wm_demo.h
#define DEMO_CONSOLE				DEMO_ON
#define DEMO_DLNA_DMR				DEMO_ON

5)要增大音箱缓存buffer，修改宏MUSIC_BUF_MAX_INDX的大小:\App\demo\wm_dlna_mediarender_demo_vs1053.c
#define    MUSIC_BUF_MAX_INDX     60 /*依实际剩余内存的大小来设置，目前最大可设置到120*/

注意：
DLNA为DEMO功能，由于内存申请较多，功能已做了很多裁剪，升级等功能已经关闭，如果要升级更新文件需要通过RAM DOWNLOAD方式下载正常固件再升级
