echo off
xcopy /y tl6_sdk.sct ..\..\Tools\Keil
xcopy /y wm_config.h ..\..\Include
xcopy /y wm_uart.h ..\..\Include
xcopy /y wifi.lib ..\..\Lib\Keil
xcopy /y wifi_costdown.lib ..\..\Lib\Keil
xcopy /y wmdlna.lib ..\..\Lib\Keil

del tl6_sdk.sct
del wm_config.h
del wm_uart.h
del wifi.lib
del wifi_costdown.lib
del wmdlna.lib