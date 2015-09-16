/***************************************************************************** 
* 
* File Name : wm_rtos_demo.c 
* 
* Description: freertos demo function 
* 
* Copyright (c) 2014 Winner Micro Electronic Design Co., Ltd. 
* All rights reserved. 
* 
* Author : dave
* 
* Date : 2014-8-27
*****************************************************************************/ 

#include <string.h>
#include "wm_include.h"
#include "FreeRTOS.h"
#include "task.h"
#include "rtosqueue.h"
#include "semphr.h"
#include "rtostimers.h"
#include "wm_timer.h"
#if 0
#define mainDELAY_LOOP_COUNT	1000000

void vTask2(void *pvParameters)
{
	const char *pcTaskName = "Task 2 is running\n";
	volatile unsigned long ul;

	for(;;)
	{
		printf("%s",pcTaskName);
#if 0
		for(ul = 0; ul < mainDELAY_LOOP_COUNT; ul ++)
		{
		
		}
#endif		
		vTaskDelay(200);
	}
}

void vTask1(void *pvParameters)
{
	const char *pcTaskName = "Task 1 is running\n";
	volatile unsigned long ul;
	printf("\nentry task 1\n");
    
#if 1
	xTaskCreate(vTask2,
				"Task 2",
				100,
				NULL,
				1,
				NULL);
#endif
	for(;;)
	{
		printf("%s",pcTaskName);
#if 0		
		for(ul = 0; ul < mainDELAY_LOOP_COUNT; ul ++)
		{
		
		}
#endif
		vTaskDelay(100);
	}
}

xQueueHandle xQueue;
void *queue_demo[5];

#define mainSENDER_1	'1'
#define mainSENDER_2	'2'
#if 0
typedef struct{
	unsigned int ucValue;
	unsigned int ucSource;
}xData;

static const xData xStructsToSend[2]=
{
	{100, mainSENDER_1},
	{200, mainSENDER_2}
};
#endif
static void vSenderTask(void *pvParameters)
{
	long lValueToSend;
	portBASE_TYPE xStatus;
//	const portTickType xTicksToWait = 1000/portTICK_RATE_MS;

	lValueToSend = (long)pvParameters;

	for(;;)
	{
	//	printf("\nparam=%x,%x,%x\n",pvParameters,((xData*)pvParameters)->ucValue,((xData*)pvParameters)->ucSource);
	//	xStatus = xQueueSend(xQueue,pvParameters, xTicksToWait);
	printf("\nlvalueto send=%d\n",lValueToSend);
		xStatus = tls_os_queue_send(xQueue,(void *)lValueToSend,0);
		//xStatus = tls_os_queue_send(xQueue,pvParameters,0);
		//printf("\nsend Status = %x\n",xStatus);
		//if(xStatus != pdPASS)
		if(xStatus != TLS_OS_SUCCESS)
		{
			printf("\nsend err\n");
			//vTaskDelay(5);
		}
		//taskYIELD();
		//vTaskDelay(50);
		tls_os_time_delay(50);
	}
}

static void vReceiverTask(void *pvParameters)
{
	long lReceivedValue;
	portBASE_TYPE xStatus;
//	xData *xReceivedStructures;

//	int msglen;

	for(;;)
	{
#if 0	
		msglen = uxQueueMessagesWaiting(xQueue);
		if(msglen != 3)
		{
			printf("\nqueue is full");
		}
#endif		
		//xStatus = xQueueReceive(xQueue, &xReceivedStructures, 0);
		xStatus = tls_os_queue_receive(xQueue, (void **)&lReceivedValue, 0, 0);
		//printf("r %x\n",lReceivedValue);
		//xReceivedStructures = (xData *)lReceivedValue;
				
		if(xStatus == TLS_OS_SUCCESS)
		//if(xStatus == pdPASS)
		{
#if 0		
			if(xReceivedStructures->ucSource== mainSENDER_1)
			{
				printf("\nFrom Sender 1=%d\n",xReceivedStructures->ucValue);
			}
			else
			{
				printf("\nFrom Sender 2=%d\n",xReceivedStructures->ucValue);
			}
#endif
			printf("\nreceived value==%d\n",lReceivedValue);
		}
		else
		{
			printf("\ncan not receive\n");
		}
	}
}


xSemaphoreHandle xBinarySemaphore;

static void vHandlerTask(void *pvParameters)
{
	for(;;)
	{
		//xSemaphoreTake(xBinarySemaphore, portMAX_DELAY);
		tls_os_sem_acquire(xBinarySemaphore,0);

		printf("\nHandler task-processing event\n");
	}
}

static void vExampleInterruptHandler(void)
{
//	static portBASE_TYPE xHigherPriorityTaskWoken = pdFALSE;

	tls_timer_stop();
	//xSemaphoreGive(xBinarySemaphore);
#if 0
	xSemaphoreGiveFromISR(xBinarySemaphore, &xHigherPriorityTaskWoken);
	xSemaphoreGiveFromISR(xBinarySemaphore, &xHigherPriorityTaskWoken);
	xSemaphoreGiveFromISR(xBinarySemaphore, &xHigherPriorityTaskWoken);

	if(xHigherPriorityTaskWoken == pdTRUE)
	{
		vTaskSwitchContext();
	}
#endif
#if 1
	tls_os_sem_release(xBinarySemaphore);
	tls_os_sem_release(xBinarySemaphore);
	tls_os_sem_release(xBinarySemaphore);
#endif	
	tls_timer_start(1000*1000);
}
#if 1	//测试timer
 #define NUM_TIMERS 1
  // An array to hold handles to the created timers.
  tls_os_timer_t *xTimers[ NUM_TIMERS ];
 
 // An array to hold a count of the number of times each timer expires.
 long lExpireCounters[ NUM_TIMERS ] = { 0 };
 // Define a callback function that will be used by multiple timer instances.
 // The callback function does nothing but count the number of times the
 // associated timer expires, and stop the timer once the timer has expired
 // 10 times.
void vTimerCallback( xTimerHandle pxTimer,void *parg )
{
	long lArrayIndex;
//	const long xMaxExpiryCountBeforeStopping = 10;
  	   // Optionally do something if the pxTimer parameter is NULL.
	configASSERT( pxTimer );
 	
     // Which timer expired?
     lArrayIndex = ( long ) pvTimerGetTimerID( pxTimer );
	 printf("\ntimer %d come\n",lArrayIndex);
      // Increment the number of times that pxTimer has expired.
     lExpireCounters[ lArrayIndex ] += 1;

     // If the timer has expired 10 times then stop it from running.
     if( 1)//lExpireCounters[ lArrayIndex ] == xMaxExpiryCountBeforeStopping )
     {
     	printf("\ntimer %d stoped\n",lArrayIndex);
         // Do not use a block time if calling a timer API function from a
         // timer callback function, as doing so could cause a deadlock!
         //xTimerStop( pxTimer, 0 );
        tls_os_timer_stop(pxTimer);
		 lExpireCounters[ lArrayIndex ] = 0;
		 printf("\nchange timer\n");
        tls_os_timer_change(pxTimer,1000);
     }
}

#endif
#define RTOS_DEMO_STK_SIZE	100
static OS_STK SendTask1Stk[RTOS_DEMO_STK_SIZE]; 
static OS_STK SendTask2Stk[RTOS_DEMO_STK_SIZE]; 
static OS_STK ReceiveTask1Stk[RTOS_DEMO_STK_SIZE]; 

void rtosdemo(void)
{
printf("\nrtos demo\n");
#if 0
	
	xTaskCreate(vTask1,
				"Task 1",
				100,
				NULL,
				1,
				NULL);

	xTaskCreate(vTask2,
				"Task 2",
				100,
				NULL,
				1,
				NULL);
#endif
#if 0	//测试消息队列
	//xQueue = xQueueCreate(3, sizeof(xData));
	tls_os_queue_create(&xQueue,queue_demo,3,0);
	
	if(xQueue != NULL)
	{
		//xTaskCreate(vSenderTask, "Sender1", 1000, &(xStructsToSend[0]), 2, NULL);
#if 1
		tls_os_task_create(NULL,
			"Sender1",
			vSenderTask,
			(void *)100,//&(xStructsToSend[0]),
			//(void *)NULL,			
			(void *)SendTask1Stk,
			RTOS_DEMO_STK_SIZE*4,
			2,
			0);
#endif		
//		xTaskCreate(vSenderTask, "Sender2", 1000, &(xStructsToSend[1]), 2, NULL);
#if 1		
		tls_os_task_create(NULL,
			"Sender2",
			vSenderTask,
			(void *)200,//&(xStructsToSend[1]),
			//(void *)NULL,			
			(void *)SendTask2Stk,
			RTOS_DEMO_STK_SIZE*4,
			3,
			0);
#endif
//		xTaskCreate(vReceiverTask,"Receiver", 1000, NULL, 2, NULL);
#if 1		
		tls_os_task_create(NULL,
			"Receiver",
			vReceiverTask,
			NULL,
			//NULL,
			(void *)ReceiveTask1Stk,
			RTOS_DEMO_STK_SIZE*4,
			4,
			0);
#endif
	}
	else
	{}
#endif	

//测试二值信号量
#if 0
	//vSemaphoreCreateBinary(xBinarySemaphore);
//	xBinarySemaphore = xSemaphoreCreateCounting(10,0);
	tls_os_sem_create(&xBinarySemaphore,0);
	tls_timer_irq_register(vExampleInterruptHandler);
	tls_timer_start(1000*1000);

	if(xBinarySemaphore != NULL)
	{
		//xTaskCreate(vHandlerTask, "Handler", 1000, NULL, 3, NULL);
		tls_os_task_create(NULL,
			"Handler",
			vHandlerTask,
			(void *)NULL,
			//NULL,
			(void *)ReceiveTask1Stk,
			RTOS_DEMO_STK_SIZE*4,
			3,
			0);
	}
#endif
#if 1
//测试timer
	long x;
 
      // Create then start some timers.  Starting the timers before the scheduler
      // has been started means the timers will start running immediately that
      // the scheduler starts.
      for( x = 0; x < NUM_TIMERS; x++ )
      {

	tls_os_timer_create(&xTimers[x],
            vTimerCallback,
            NULL,
          //  ( 100 * (x+1) ), 
          500,
            FALSE,
            "Timer");
	  

 	printf("\nxtimer %d==%x\n",x,xTimers[x]);
          if( xTimers[ x ] == NULL )
          {
              // The timer was not created.
          }
          else
          {
              // Start the timer.  No block time is specified, and even if one was
              // it would be ignored because the scheduler has not yet been
              // started.
             // if( xTimerStart( xTimers[ x ], 0 ) != pdPASS )
             tls_os_timer_start(xTimers[x]);
              {
                  // The timer could not be set into the Active state.
              }
          }
      }
#endif	  
}
#endif
