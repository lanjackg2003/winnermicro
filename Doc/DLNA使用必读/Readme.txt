DLNA���������
1)��ѹDLNAѹ��������ǰ�ļ���

2)ִ��DLNA�������ļ�����ǰ���̵���Ӧ�ļ��ᱻ����
tl6_sdk.sct
wifi.lib
wifi_costdown.lib
wm_config.h
wm_uart.h
wmdlna.lib

3)��wmdlna.lib��ӵ�SDK����

4)��DEMO���أ�\App\demo\wm_demo.h
#define DEMO_CONSOLE				DEMO_ON
#define DEMO_DLNA_DMR				DEMO_ON

5)Ҫ�������仺��buffer���޸ĺ�MUSIC_BUF_MAX_INDX�Ĵ�С:\App\demo\wm_dlna_mediarender_demo_vs1053.c
#define    MUSIC_BUF_MAX_INDX     60 /*��ʵ��ʣ���ڴ�Ĵ�С�����ã�Ŀǰ�������õ�120*/

ע�⣺
DLNAΪDEMO���ܣ������ڴ�����϶࣬���������˺ܶ�ü��������ȹ����Ѿ��رգ����Ҫ���������ļ���Ҫͨ��RAM DOWNLOAD��ʽ���������̼�������
