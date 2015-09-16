#include <string.h>
#include "wm_include.h"
#include "wm_http_fwup.h"
#if DEMO_HTTP_XML_PARSE
#include "../Expat2.1.0/expat.h"
#endif
#if DEMO_HTTP_JSON_PARSE
#include "../libjson0.8/json.h"
#elif DEMO_HTTP_SXML_PARSE
#include "../sxmlc4.0.5/sxmlutils.h"
#include "../sxmlc4.0.5/sxmlc.h"
#include "../sxmlc4.0.5/sxmlsearch.h"
#endif

#if DEMO_HTTP
#define    HTTP_CLIENT_BUFFER_SIZE   1024
extern u8 RemoteIp[4];

#if DEMO_HTTP_XML_PARSE
static int depth = 0;
static void XMLCALL
startElement(void *userData, const char *name, const char **atts)
{
  int i;
  int *depthPtr = (int *)userData;
  printf("\n");
  for (i = 0; i < *depthPtr; i++)
    printf("\t");
  printf("<%s>", name);
  *depthPtr += 1;
}

static void XMLCALL
endElement(void *userData, const char *name)
{
  int i;
  int *depthPtr = (int *)userData;
  *depthPtr -= 1;
  printf("\n");
  for (i = 0; i < *depthPtr; i++)
    printf("\t");
  printf("</%s>", name);
}

static int xmlParseInit(XML_Parser *parser )
{
  depth = 0;
  *parser = XML_ParserCreate(NULL);
  XML_SetUserData(*parser, &depth);
  XML_SetElementHandler(*parser, startElement, endElement);
	return 0;
}

static int xmlParse(XML_Parser parser, char* buf, int len, int done)
{
  do {
    if (XML_Parse(parser, buf, len, done) == XML_STATUS_ERROR) {
     printf("%s at line %d\n",
              XML_ErrorString(XML_GetErrorCode(parser)),
              (int)XML_GetCurrentLineNumber(parser));
      return 1;
    }
  } while (0);
  if(done)
    XML_ParserFree(parser);
  return 0;
}

#elif DEMO_HTTP_SXML_PARSE
static const char* tag_type_names[] = {
	"TAG_NONE",
	"TAG_PARTIAL",
	"TAG_FATHER",
	"TAG_SELF",
	"TAG_END",
	"TAG_PROLOG",
	"TAG_COMMENT",
	"TAG_CDATA",
	"TAG_DOCTYPE"
};
int start_node(const XMLNode* node, SAX_Data* sd)
{
	int i;
	printf("Start node %s <%s>\n", node->tag_type == TAG_USER+1 ? "MONTAG" : tag_type_names[node->tag_type], node->tag);
	for (i = 0; i < node->n_attributes; i++)
		printf("\t%s=\"%s\"\n", node->attributes[i].name, node->attributes[i].value);
	return true;
}

int end_node(const XMLNode* node, SAX_Data* sd)
{
	printf("End node %s <%s>\n", node->tag_type == TAG_USER+1 ? "MONTAG" : tag_type_names[node->tag_type], node->tag);
	return true;
}

int new_text(const SXML_CHAR* text, SAX_Data* sd)
{
	SXML_CHAR* p = (SXML_CHAR*)text;
	while(*p && sx_isspace(*p++)) ;
	*p--;
	if (*p)
		sx_printf(C2SX("Text: [%s]\n"), p);
	return true;
}

int allin1(XMLEvent event, const XMLNode* node, SXML_CHAR* text, const int n, SAX_Data* sd)
{
	switch(event) {
		case XML_EVENT_START_DOC: printf("Document start\n\n"); return true;
		case XML_EVENT_START_NODE: return start_node(node, sd);
		case XML_EVENT_END_NODE: return end_node(node, sd);
		case XML_EVENT_TEXT: return new_text(text, sd);
		case XML_EVENT_ERROR: printf("%s:%d: ERROR %d\n", sd->name, sd->line_num, n); return true;
		case XML_EVENT_END_DOC: printf("\nDocument end\n"); return true;
		default: return true;
	}
}

void sxml_parse_all(char * buf)
{
	SAX_Callbacks sax;

	SAX_Callbacks_init(&sax);
	//sax.start_node = NULL;//start_node;
	//sax.end_node = NULL;//end_node;
	//sax.new_text = NULL;//new_text;
	sax.all_event = allin1;
	if (!XMLDoc_parse_buffer_SAX(C2SX(buf), C2SX("Buffer1"), &sax, NULL))
		printf("Error while loading\n");
}

#endif //DEMO_HTTP_XML_PARSE

#if DEMO_HTTP_JSON_PARSE
static int printchannel(void *userdata, const char *data, u32 length)
{
	printf("%.*s", length, data); 
	return 0;
}
static int prettyprint(void *userdata, int type, const char *data, u32 length)
{
	json_printer *printer = userdata;
	//printf("type=%d, data=%s, length=%d\n", type, data, length);
	return json_print_pretty(printer, type, data, length);
}
static int jsonParseInit(json_parser *parser, json_printer *printer)
{
	json_config config;
//printf("jsonParseInit Start...\n");
	memset(&config, 0, sizeof(json_config));
	config.max_nesting = 0;
	config.max_data = 0;
	config.allow_c_comments = 1;
	config.allow_yaml_comments = 1;
	int ret;
	/* initialize printer and parser structures */
	ret = json_print_init(printer, printchannel, NULL);
	if (ret) {
		printf("error: initializing printer failed: [code=%d]\n", ret);
		return ret;
	}

	ret = json_parser_init(parser, &config, &prettyprint, printer);
	if (ret) {
		printf("error: initializing parser failed: [code=%d]\n", ret);
		return ret;
	}
	return 0;
}

static int jsonParse(json_parser *parser, json_printer *printer, char* buf, int len, int done)
{
	int ret;
	u32 processed;
//printf("jsonParse: %s, len=%d\n", buf, len);
	ret = json_parser_string(parser, buf, len, &processed);
	if(ret)
	{
		printf("jsonParse: Error ret=%d\n", ret);
	}
	if(done)
	{
		json_parser_free(parser);
		json_print_free(printer);
	}
	return ret;
}
#endif //DEMO_HTTP_JSON_PARSE

UINT32   http_snd_req(HTTPParameters ClientParams, HTTP_VERB verb, CHAR* pSndData, u8 parseXmlJson)
{
		INT32                   nRetCode;
    UINT32                  nSize,nTotal = 0;
    CHAR*                   Buffer = NULL;
    HTTP_SESSION_HANDLE     pHTTP;
    UINT32                  nSndDataLen ;
#if DEMO_HTTP_XML_PARSE
    XML_Parser parser;
#elif DEMO_HTTP_SXML_PARSE
    CHAR * buf_cache = NULL;
    UINT32 cur_pos = 0;
#endif
#if DEMO_HTTP_JSON_PARSE
    json_parser jsonParser;
    json_printer printer;
#endif
    do
    {
#if !DEMO_HTTP_XML_PARSE && DEMO_HTTP_SXML_PARSE
        buf_cache = (CHAR*)tls_mem_alloc(HTTP_CLIENT_BUFFER_SIZE);
        if(buf_cache == NULL)
            return HTTP_CLIENT_ERROR_NO_MEMORY;
        memset(buf_cache , 0, HTTP_CLIENT_BUFFER_SIZE);
#endif
        Buffer = (CHAR*)tls_mem_alloc(HTTP_CLIENT_BUFFER_SIZE);
        if(Buffer == NULL)
        {
#if !DEMO_HTTP_XML_PARSE && DEMO_HTTP_SXML_PARSE
            tls_mem_free(buf_cache);
#endif
            return HTTP_CLIENT_ERROR_NO_MEMORY;
        }
        memset(Buffer, 0, HTTP_CLIENT_BUFFER_SIZE);
        printf("\nHTTP Client v1.0\n\n");
        nSndDataLen = (pSndData==NULL ? 0 : strlen(pSndData));
        // Open the HTTP request handle
        pHTTP = HTTPClientOpenRequest(0);
        if(!pHTTP)
        {
            nRetCode =  HTTP_CLIENT_ERROR_INVALID_HANDLE;
            break;
        }
        // Set the Verb
        nRetCode = HTTPClientSetVerb(pHTTP,verb);
        if(nRetCode != HTTP_CLIENT_SUCCESS)
        {
            break;
        }
#if TLS_CONFIG_HTTP_CLIENT_AUTH
        // Set authentication
        if(ClientParams.AuthType != AuthSchemaNone)
        {
            if((nRetCode = HTTPClientSetAuth(pHTTP,ClientParams.AuthType,NULL)) != HTTP_CLIENT_SUCCESS)
            {
                break;
            }

            // Set authentication
            if((nRetCode = HTTPClientSetCredentials(pHTTP,ClientParams.UserName,ClientParams.Password)) != HTTP_CLIENT_SUCCESS)
            {
                break;
            }
        }
#endif //TLS_CONFIG_HTTP_CLIENT_AUTH
#if TLS_CONFIG_HTTP_CLIENT_PROXY
        // Use Proxy server
        if(ClientParams.UseProxy == TRUE)
        {
            if((nRetCode = HTTPClientSetProxy(pHTTP,ClientParams.ProxyHost,ClientParams.ProxyPort,NULL,NULL)) != HTTP_CLIENT_SUCCESS)
            {

                break;
            }
        }
#endif //TLS_CONFIG_HTTP_CLIENT_PROXY
	 if((nRetCode = HTTPClientSendRequest(pHTTP,ClientParams.Uri,pSndData,nSndDataLen,verb==VerbPost || verb==VerbPut,0,0)) != HTTP_CLIENT_SUCCESS)
        {
            break;
        }
        // Retrieve the the headers and analyze them
        if((nRetCode = HTTPClientRecvResponse(pHTTP,30)) != HTTP_CLIENT_SUCCESS)
        {
            break;
        }
	 printf("Start to receive data from remote server...\n");
#if DEMO_HTTP_XML_PARSE
        if(parseXmlJson == 1)
            xmlParseInit(&parser);
#endif
#if DEMO_HTTP_JSON_PARSE
        if(parseXmlJson == 2)
            jsonParseInit(&jsonParser, &printer);
#endif
        // Get the data until we get an error or end of stream code
        while(nRetCode == HTTP_CLIENT_SUCCESS || nRetCode != HTTP_CLIENT_EOS)
        {
            // Set the size of our buffer
            nSize = HTTP_CLIENT_BUFFER_SIZE;   
            // Get the data
            nRetCode = HTTPClientReadData(pHTTP,Buffer,nSize,300,&nSize);
            if(nRetCode != HTTP_CLIENT_SUCCESS && nRetCode != HTTP_CLIENT_EOS)
                break;
            printf("%s", Buffer);
#if DEMO_HTTP_XML_PARSE
            if(parseXmlJson == 1)
                xmlParse(parser, Buffer, nSize, nRetCode == HTTP_CLIENT_EOS);
#elif DEMO_HTTP_SXML_PARSE
            if(parseXmlJson == 1)
            {
                if(cur_pos + nSize < HTTP_CLIENT_BUFFER_SIZE-1)
                {
                    memcpy(buf_cache+cur_pos, Buffer, nSize);
                    cur_pos += nSize;
                    if(nRetCode == HTTP_CLIENT_EOS)
                        sxml_parse_all(buf_cache);
                }
            }
#endif
#if DEMO_HTTP_JSON_PARSE
            if(parseXmlJson == 2)
                jsonParse(&jsonParser, &printer, Buffer, nSize, nRetCode == HTTP_CLIENT_EOS);
#endif
            nTotal += nSize;
        }
    } while(0); // Run only once
    tls_mem_free(Buffer);
#if !DEMO_HTTP_XML_PARSE && DEMO_HTTP_SXML_PARSE
    tls_mem_free(buf_cache);
#endif
    if(pHTTP)
        HTTPClientCloseRequest(&pHTTP);
    if(ClientParams.Verbose == TRUE)
    {
        printf("\n\nHTTP Client terminated %d (got %d kb)\n\n",nRetCode,(nTotal/ 1024));
    }
    return nRetCode;
}

UINT32 http_get(HTTPParameters ClientParams)
{
    return http_snd_req(ClientParams, VerbGet, NULL, 0);
}

UINT32 http_post(HTTPParameters ClientParams, CHAR* pSndData)
{
    return http_snd_req(ClientParams, VerbPost, pSndData, 0);
}

UINT32 http_put(HTTPParameters ClientParams, CHAR* pSndData)
{
    return http_snd_req(ClientParams, VerbPut, pSndData, 0);
}

#if DEMO_HTTP_XML_PARSE || DEMO_HTTP_SXML_PARSE
int http_parse_xml(char *buf)
{
    HTTPParameters httpParams;
    memset(&httpParams, 0, sizeof(HTTPParameters));
    httpParams.Uri = (CHAR*)tls_mem_alloc(128);
    if(httpParams.Uri == NULL)
    {
        printf("malloc error.\n");
        return WM_FAILED;
    }
    memset(httpParams.Uri, 0, 128);
    sprintf(httpParams.Uri, "http://%d.%d.%d.%d:8080/TestWeb/welcome.xml", RemoteIp[0],RemoteIp[1],RemoteIp[2],RemoteIp[3]);
    //httpParams.ProxyHost = "61.175.96.34";
    //httpParams.ProxyPort = 9999;
    //httpParams.UseProxy = TRUE;
    httpParams.Verbose = TRUE;
    printf("Location: %s\n",httpParams.Uri);
    http_snd_req(httpParams, VerbGet, NULL, 1);
    tls_mem_free(httpParams.Uri);

    return WM_SUCCESS;
}
#endif

#if DEMO_HTTP_JSON_PARSE
int http_parse_json(char *buf)
{
    HTTPParameters httpParams;
    memset(&httpParams, 0, sizeof(HTTPParameters));
    httpParams.Uri = (CHAR*)tls_mem_alloc(128);
    if(httpParams.Uri == NULL)
    {
        printf("malloc error.\n");
        return WM_FAILED;
    }
    memset(httpParams.Uri, 0, 128);
    sprintf(httpParams.Uri, "http://%d.%d.%d.%d:8080/TestWeb/welcome.json", RemoteIp[0],RemoteIp[1],RemoteIp[2],RemoteIp[3]);
    //httpParams.ProxyHost = "61.175.96.34";
    //httpParams.ProxyPort = 9999;
    //httpParams.UseProxy = TRUE;
    httpParams.Verbose = TRUE;
    printf("Location: %s\n",httpParams.Uri);
    http_snd_req(httpParams, VerbGet, NULL, 2);
    tls_mem_free(httpParams.Uri);

    return WM_SUCCESS;
}
#endif

int http_get_demo(char *buf)
{
    HTTPParameters httpParams;
    memset(&httpParams, 0, sizeof(HTTPParameters));
    httpParams.Uri = (CHAR*)tls_mem_alloc(128);
    if(httpParams.Uri == NULL)
    {
        printf("malloc error.\n");
        return WM_FAILED;
    }
    memset(httpParams.Uri, 0, 128);
    sprintf(httpParams.Uri, "http://%d.%d.%d.%d:8080/TestWeb/", RemoteIp[0],RemoteIp[1],RemoteIp[2],RemoteIp[3]);
    //httpParams.ProxyHost = "61.175.96.34";
    //httpParams.ProxyPort = 9999;
    //httpParams.UseProxy = TRUE;
    httpParams.Verbose = TRUE;
    printf("Location: %s\n",httpParams.Uri);
    http_get(httpParams);
    tls_mem_free(httpParams.Uri);

    return WM_SUCCESS;
}
int http_post_demo(char* postData)
{
	HTTPParameters httpParams;
	extern const char HTTP_POST[];
	memset(&httpParams, 0, sizeof(HTTPParameters));
	httpParams.Uri = (CHAR*)tls_mem_alloc(128);
	if(httpParams.Uri == NULL)
	{
	    printf("malloc error.\n");
	    return WM_FAILED;
	}
	memset(httpParams.Uri, 0, 128);
	sprintf(httpParams.Uri, "http://%d.%d.%d.%d:8080/TestWeb/login.do", RemoteIp[0],RemoteIp[1],RemoteIp[2],RemoteIp[3]);
	printf("Location: %s\n",httpParams.Uri);
	httpParams.Verbose = TRUE;
	http_post(httpParams, postData + strlen(HTTP_POST));
	tls_mem_free(httpParams.Uri);
	return WM_SUCCESS;
}
int http_put_demo(char* putData)
{
	HTTPParameters httpParams;
	extern const char HTTP_PUT[];
	memset(&httpParams, 0, sizeof(HTTPParameters));
	httpParams.Uri = (CHAR*)tls_mem_alloc(128);
	if(httpParams.Uri == NULL)
	{
	    printf("malloc error.\n");
	    return WM_FAILED;
	}
	memset(httpParams.Uri, 0, 128);
	sprintf(httpParams.Uri, "http://%d.%d.%d.%d:8080/TestWeb/login_put.do", RemoteIp[0],RemoteIp[1],RemoteIp[2],RemoteIp[3]);
	printf("Location: %s\n",httpParams.Uri);
	httpParams.Verbose = TRUE;
	http_put(httpParams, putData + strlen(HTTP_PUT));
	tls_mem_free(httpParams.Uri);
	return WM_SUCCESS;
}

int http_fwup_demo(char *buf)
{
	HTTPParameters httpParams;
	memset(&httpParams, 0, sizeof(HTTPParameters));
	httpParams.Uri = (CHAR*)tls_mem_alloc(128);
	if(httpParams.Uri == NULL)
	{
	    printf("malloc error.\n");
	    return WM_FAILED;
	}
	memset(httpParams.Uri, 0, 128);
	sprintf(httpParams.Uri, "http://%d.%d.%d.%d:8080/TestWeb/cuckoo.do", RemoteIp[0],RemoteIp[1],RemoteIp[2],RemoteIp[3]);
	printf("Location: %s\n",httpParams.Uri);
	httpParams.Verbose = TRUE;
	http_fwup(httpParams);
	tls_mem_free(httpParams.Uri);

	return WM_SUCCESS;
}

#endif //DEMO_HTTP

