#ifndef KII_H
#define KII_H

#define KII_SITE_SIZE 2
#define KII_HOST_SIZE 64
#define KII_APPID_SIZE 8
#define KII_APPKEY_SIZE 32

#define KII_ACCESS_TOKEN_SIZE 44
#define KII_DEVICE_VENDOR_ID 64 // matches [a-zA-Z0-9-_\\.]{3,64}
#define KII_PASSWORD_SIZE 50    // Matches ^[\\u0020-\\u007E]{4,50}
#define KII_OBJECTID_SIZE 36
#define KII_DATA_TPYE_SIZE 36
#define KII_UPLOAD_ID_SIZE 46
#define KII_BUCKET_NAME_SIZE 64

#define KII_SOCKET_BUF_SIZE 2048

typedef enum { KII_APP_SCOPE = 0, KII_THING_SCOPE = 1 } kii_scope_e;

typedef void (*kiiPush_recvMsgCallback)(char* jsonBuf, int rcvdCounter);

/*****************************************************************************
*
*  kii_init
*
*  \param  site - the input of site name, should be one of "CN", "JP", "US", "SG"
*              appID - the input of Application ID
*              objectID - the input of Application Key
*
*  \return  0:success; -1: failure
*
*  \brief  Initializes Kii
*
*****************************************************************************/
extern int kii_init(char* site, char* appID, char* appKey);

/*****************************************************************************
*
*  kiiDev_getToken
*
*  \param  vendorDeviceID - the input of identification of the device
*               password - the input of password
*
*  \return 0:success; -1: failure
*
*  \brief  Gets token
*
*****************************************************************************/
extern int kiiDev_getToken(char* deviceVendorID, char* password);

/*****************************************************************************
*
*  kiiDev_register
*
*  \param  vendorDeviceID - the input of identification of the device
*               deviceType - the input of device type
*               password - the input of password
*
*  \return 0:success; -1: failure
*
*  \brief  Registers device
*
*****************************************************************************/
extern int kiiDev_register(char* vendorDeviceID, char* deviceType, char* password);

/*****************************************************************************
*
*  kiiDev_getIPAddress
*
*  \param  ipAddress - the info of IP address
*
*  \return 0:success; -1: failure
*
*  \brief  Gets external IP address
*
*****************************************************************************/
int kiiDev_getIPAddress(char* ipAddress);

/*****************************************************************************
*
*  kiiObj_create
*
*  \param  scope - bucket scope
*               bucketName - the input of bucket name
*               jsonObject - the input of object with json format
*               dataType - the input of data type, the format should be like "mydata"
*               objectID - the output of objectID
*
*  \return 0:success; -1: failure
*
*  \brief  Creates object
*
*****************************************************************************/
extern int kiiObj_create(int scope, char* bucketName, char* jsonObject, char* dataType, char* objectID);

/*****************************************************************************
*
*  kiiObj_createWithID
*
*  \param  scope - bucket scope
*               bucketName - the input of bucket name
*               jsonObject - the input of object with json format
*               dataType - the input of data type, the format should be like "mydata"
*               objectID - the input of objectID
*
*  \return  0:success; -1: failure
*
*  \brief  Creates a new object with an ID
*
*****************************************************************************/
extern int kiiObj_createWithID(int scope, char* bucketName, char* jsonObject, char* dataType, char* objectID);

/*****************************************************************************
*
*  kiiObj_fullyUpdate
*
*  \param  scope - bucket scope
*               bucketName - the input of bucket name
*               jsonObject - the input of object with json format
*               dataType - the input of data type, the format should be like "mydata"
*               objectID - the input of objectID
*
*  \return  0:success; -1: failure
*
*  \brief  Fully updates an object
*
*****************************************************************************/
extern int kiiObj_fullyUpdate(int scope, char* bucketName, char* jsonObject, char* dataType, char* objectID);

/*****************************************************************************
*
*  kiiObj_partiallyUpdate
*
*  \param  scope - bucket scope
*               bucketName - the input of bucket name
*               jsonObject - the input of object with json format
*               objectID - the input of objectID
*
*  \return  0:success; -1: failure
*
*  \brief  Partially updates an object
*
*****************************************************************************/
extern int kiiObj_partiallyUpdate(int scope, char* bucketName, char* jsonObject, char* objectID);

/*****************************************************************************
*
*  kiiObj_uploadBodyAtOnce
*
*  \param  scope - bucket scope
*               bucketName - the input of bucket name
*               objectID - the input of objectID
*               dataType - the input of data type, the format should be like "image/jpg"
*               data - raw data
*               length - raw data length
*
*  \return 0:success; -1: failure
*
*  \brief  Uploads object body at once
*
*****************************************************************************/
extern int kiiObj_uploadBodyAtOnce(int scope,
                                   char* bucketName,
                                   char* objectID,
                                   char* dataType,
                                   unsigned char* data,
                                   unsigned int length);

/*****************************************************************************
*
*  kiiObj_uploadBodyInit
*
*  \param  scope - bucket scope
*               bucketName - the input of bucket name
*               objectID - the input of objectID
*               uploadID - the output of uploadID
*
*  \return 0:success; -1: failure
*
*  \brief  Initializes "uploading an object body in multiple pieces"
*
*****************************************************************************/
extern int kiiObj_uploadBodyInit(int scope, char* bucketName, char* objectID, char* uploadID);

/*****************************************************************************
*
*  kiiObj_uploadBody
*
*  \param  scope - bucket scope
*               bucketName - the input of bucket name
*               objectID - the input of objectID
*               uploadID - the input of uploadID
*               dataType - the input of data type, the format should be like "image/jpg"
*               position - data position
*               length - this  piece of data length
*               totalLength - the total object body length
*               data - raw data
*
*  \return 0:success; -1: failure
*
*  \brief  Uploads a piece of data
*
*****************************************************************************/
extern int kiiObj_uploadBody(int scope,
                             char* bucketName,
                             char* objectID,
                             char* uploadID,
                             char* dataType,
                             unsigned int position,
                             unsigned int length,
                             unsigned int totalLength,
                             unsigned char* data);

/*****************************************************************************
*
*  kiiObj_uploadBody
*
*  \param  scope - bucket scope
*               bucketName - the input of bucket name
*               objectID - the input of objectID
*               uploadID - the input of uploadID
*               committed - 0: cancelled; 1: committed
*
*  \return 0:success; -1: failure
*
*  \brief  Commits or cancels this uploading
*
*****************************************************************************/
extern int kiiObj_uploadBodyCommit(int scope, char* bucketName, char* objectID, char* uploadID, int committed);

/*****************************************************************************
*
*  kiiObj_retrieve
*
*  \param  scope - bucket scope
*               bucketName - the input of bucket name
*               objectID - the input of objectID
*               jsonObject - the output of object with json format
*               length - the buffer length of jsonObject
*
*  \return 0:success; -1: failure
*
*  \brief  Retrieves object with objectID
*
*****************************************************************************/
extern int kiiObj_retrieve(int scope, char* bucketName, char* objectID, char* jsonObject, unsigned int length);

/*****************************************************************************
*
*  kiiObj_downloadBodyAtOnce
*
*  \param  scope - bucket scope
*               bucketName - the input of bucket name
*               objectID - the input of objectID
*               data - raw data
*               length - the buffer lengh for object body
*               actualLength - the actual length of received body
*  \return 0:success; -1: failure
*
*  \brief  Downloads an object body at once
*
*****************************************************************************/
extern int kiiObj_downloadBodyAtOnce(int scope,
                                     char* bucketName,
                                     char* objectID,
                                     unsigned char* data,
                                     unsigned int length,
                                     unsigned int* actualLength);

/*****************************************************************************
*
*  kiiObj_downloadBody
*
*  \param  scope - bucket scope
*               bucketName - the input of bucket name
*               objectID - the input of objectID
*               position - the downloading position of body
*               length - the downloading length of body
*               data - the output data of received body
*               actualLength - the actual length of received body
*               totalLength - the output of total body length
*
*  \return 0:success; -1: failure
*
*  \brief  Downloads an object body in multiple pieces
*
*****************************************************************************/
extern int kiiObj_downloadBody(int scope,
                               char* bucketName,
                               char* objectID,
                               unsigned int position,
                               unsigned int length,
                               unsigned char* data,
                               unsigned int* actualLength,
                               unsigned int* totalLength);

/*****************************************************************************
*
*  kiiPush_subscribeBucket
*
*  \param  scope - bucket scope
*               bucketID - the bucket ID
*
*  \return 0:success; -1: failure
*
*  \brief  Subscribes bucket
*
*****************************************************************************/
extern int kiiPush_subscribeBucket(int scope, char* bucketID);

/*****************************************************************************
*
*  kiiPush_subscribeTopic
*
*  \param: scope - topic scope
*               topicID - the topic ID
*
*  \return 0:success; -1: failure
*
*  \brief  Subscribes thing scope topic
*
*****************************************************************************/
extern int kiiPush_subscribeTopic(int scope, char* topicID);

/*****************************************************************************
*
*  kiiPush_createTopic
*
*  \param: scope - topic scope
*               topicID - the topic ID
*
*  \return 0:success; -1: failure
*
*  \brief  Creates thing scope topic
*
*****************************************************************************/
extern int kiiPush_createTopic(int scope, char* topicID);

/*****************************************************************************
*
*  KiiPush_init
*
*  \param: recvMsgtaskPrio - the priority of task for receiving message
*               pingReqTaskPrio - the priority of task for "PINGREQ" task
*               callback - the call back function for processing the push message received
*
*  \return 0:success; -1: failure
*
*  \brief  Initializes push
*
*****************************************************************************/
extern int KiiPush_init(unsigned int taskPrio, unsigned int pingReqTaskPrio, kiiPush_recvMsgCallback callback);

/*****************************************************************************
*
*  kiiExt_extension
*
*  \param  endpointName - the endpoint name
*              jsonObject - the input of object with json format
*
*  \return 0:success; -1: failure
*
*  \brief  Executes the server extension code
*
*****************************************************************************/
extern int kiiExt_extension(char* endpointName, char* jsonObject);

#endif
