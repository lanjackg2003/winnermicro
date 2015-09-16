#include <string.h>
#include "wm_include.h"
#if DEMO_KII
#include "kii.h"
#include "light.h"
#include "light_if.h"
#include "kii_demo.h"

volatile int toStop = 0;

int kiiDemo_test(char *buf)
{
	(void) buf;

	while(1)
	{
		if(light_init() < 0)
		{
			printf("Initialize light failed\r\n");
			tls_os_time_delay(10*HZ);
			continue;
		}
		else
		{
			printf("Initialize light success\r\n");
			return 0;
		}
	}
}
#endif

