/*
 * @Author: yj 
 * @email: shiliu.yang@tuya.com
 * @LastEditors: yj 
 * @file name: tuya_device.c
 * @Description: template demo for SDK WiFi & BLE for BK7231T
 * @Copyright: HANGZHOU TUYA INFORMATION TECHNOLOGY CO.,LTD
 * @Company: http://www.tuya.com
 * @Date: 2021-01-23 16:33:00
 * @LastEditTime: 2021-01-27 17:00:00
 */

#include "new_common.h"
#include "logging.h"
#include "http_client.h"

#define bk_printf(x, ...) addLog(x, ##__VA_ARGS__)


/*
#define _TUYA_DEVICE_GLOBAL
*/
/* Includes ------------------------------------------------------------------*/
/*#include "uni_log.h"
#include "tuya_iot_wifi_api.h"
#include "tuya_hal_system.h"
#include "tuya_iot_com_api.h"
#include "tuya_cloud_com_defs.h"
#include "gw_intf.h"
#include "gpio_test.h"
#include "tuya_gpio.h"
#include "tuya_key.h"
#include "tuya_led.h"
#include "wlan_ui_pub.h"

#include "lwip/sockets.h"
#include "lwip/ip_addr.h"
#include "lwip/inet.h"

*/
#include "new_config.h"

/* Private includes ----------------------------------------------------------*/
#include "tuya_device.h"
#include "new_http.h"
#include "new_pins.h"

#include "../../beken378/func/key/multi_button.h"
#include "../../beken378/app/config/param_config.h"
#include "lwip/apps/mqtt.h"

static int cnt = 0;
static int reconnect = 0;

// Long unique device name, like OpenBK7231T_AABBCCDD
char g_deviceName[64];
// Short unique device name, like obkAABBCCDD
char g_shortDeviceName[64];



#define HTTP_SERVER_PORT            80 /*set up a tcp server,port at 20000*/

int my_fd = -1; 

int g_my_reconnect_mqtt_after_time = -1;


#define tcp_server_log(M, ...) bk_printf(M, ##__VA_ARGS__)



int unw_recv(const int fd, void *buf, u32 nbytes)
{
    fd_set readfds, errfds;
    int ret = 0;   

    if( fd < 0 ) 
    {        
        return -1;//UNW_FAIL;
    } 

    FD_ZERO( &readfds );
    FD_ZERO( &errfds ); 
    FD_SET( fd, &readfds );
    FD_SET( fd, &errfds );

    ret = select( fd+1, &readfds, NULL, &errfds, NULL);
    bk_printf("select ret:%d, %d, %d\r\n", ret, FD_ISSET( fd, &readfds ), FD_ISSET( fd, &errfds ));

    if(ret > 0 && FD_ISSET( fd, &readfds ))
        return recv(fd,buf,nbytes,0); 
    else
        return -1;//UNW_FAIL;
    
}

void tcp_client_thread( beken_thread_arg_t arg )
{
    OSStatus err = kNoErr;
    int fd = (int) arg;
    int len = 0;
    fd_set readfds, errfds, readfds2; 
    char *buf = NULL;
    char *reply = NULL;
	int replyBufferSize = 10000;
	int res;
	//char reply[8192];

    my_fd = fd;

    reply = (char*) os_malloc( replyBufferSize );
    buf = (char*) os_malloc( 1024 );
    ASSERT(buf);
    

    
    while ( 1 )
    {
           
        {
            len = recv( fd, buf, 1024, 0 );

            if ( len <= 0 )
            {
                bk_printf( "TCP Client is disconnected, fd: %d", fd );
                goto exit;
            }
  
            bk_printf( "TCP received string %s\n",buf );
            
            HTTP_ProcessPacket(buf, reply, replyBufferSize);

            ///	strcpy(buf,"[WB2S example TCP reply!]");
            len = strlen(reply);
            bk_printf( "TCP sending reply len %i\n",len );
            len = send( fd, reply, len, 0 );

            rtos_delay_milliseconds(10);
            break;
        }
    }
	
exit:
    if ( err != kNoErr ) 
		tcp_server_log( "TCP client thread exit with err: %d", err );
	
    if ( buf != NULL ) 
		os_free( buf );
    if ( reply != NULL ) 
		os_free( reply );
	
    close( fd );
    rtos_delete_thread( NULL );
}

volatile u8 test_flag = 0;
void close_tcp_client(void)
{
    bk_printf("close_tcp_client:%d, %p\r\n", my_fd, rtos_get_current_thread());
    test_flag = 1;
    close( my_fd );
    my_fd = -1;
}

/* TCP server listener thread */
void tcp_server_thread( beken_thread_arg_t arg )
{
    (void)( arg );
    OSStatus err = kNoErr;
    struct sockaddr_in server_addr, client_addr;
    socklen_t sockaddr_t_size = sizeof(client_addr);
    char client_ip_str[16];
    int tcp_listen_fd = -1, client_fd = -1;
    fd_set readfds;

    tcp_listen_fd = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP );

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;/* Accept conenction request on all network interface */
    server_addr.sin_port = htons( HTTP_SERVER_PORT );/* Server listen on port: 20000 */
    err = bind( tcp_listen_fd, (struct sockaddr *) &server_addr, sizeof(server_addr) );
    
    err = listen( tcp_listen_fd, 0 );
    
    while ( 1 )
    {
        FD_ZERO( &readfds );
        FD_SET( tcp_listen_fd, &readfds );

        select( tcp_listen_fd + 1, &readfds, NULL, NULL, NULL);

        if ( FD_ISSET( tcp_listen_fd, &readfds ) )
        {
            client_fd = accept( tcp_listen_fd, (struct sockaddr *) &client_addr, &sockaddr_t_size );
            if ( client_fd >= 0 )
            {
                os_strcpy( client_ip_str, inet_ntoa( client_addr.sin_addr ) );
                tcp_server_log( "TCP Client %s:%d connected, fd: %d", client_ip_str, client_addr.sin_port, client_fd );
                if ( kNoErr
                     != rtos_create_thread( NULL, BEKEN_APPLICATION_PRIORITY, 
							                     "TCP Clients",
                                                 (beken_thread_function_t)tcp_client_thread,
                                                 0x800, 
                                                 (beken_thread_arg_t)client_fd ) ) 
                {
                    close( client_fd );
					client_fd = -1;
                }
            }
        }
    }
	
    if ( err != kNoErr ) 
		tcp_server_log( "Server listerner thread exit with err: %d", err );
	
    close( tcp_listen_fd );
    rtos_delete_thread( NULL );
}

void connect_to_wifi(const char *oob_ssid,const char *connect_key)
{
	network_InitTypeDef_adv_st	wNetConfigAdv;

	os_memset( &wNetConfigAdv, 0x0, sizeof(network_InitTypeDef_adv_st) );
	
	os_strcpy((char*)wNetConfigAdv.ap_info.ssid, oob_ssid);
	hwaddr_aton("48:ee:0c:48:93:12", wNetConfigAdv.ap_info.bssid);
	wNetConfigAdv.ap_info.security = SECURITY_TYPE_WPA2_MIXED;
	wNetConfigAdv.ap_info.channel = 4; // leave at 0
	
	os_strcpy((char*)wNetConfigAdv.key, connect_key);
	wNetConfigAdv.key_len = os_strlen(connect_key);
	wNetConfigAdv.dhcp_mode = DHCP_CLIENT;
	wNetConfigAdv.wifi_retry_interval = 100;

	bk_wlan_start_sta_adv(&wNetConfigAdv);
  bk_printf("ssid:%s key:%s\r\n", oob_ssid, connect_key);
}



void demo_start_tcp()
{
    OSStatus err = kNoErr;

    err = rtos_create_thread( NULL, BEKEN_APPLICATION_PRIORITY, 
									"TCP_server", 
									(beken_thread_function_t)tcp_server_thread,
									0x800,
									(beken_thread_arg_t)0 );
    if(err != kNoErr)
    {
       bk_printf("create \"TCP_server\" thread failed!\r\n");
    }
}


beken_timer_t led_timer;

#ifndef LWIP_MQTT_EXAMPLE_IPADDR_INIT
#if LWIP_IPV4
#define LWIP_MQTT_EXAMPLE_IPADDR_INIT = IPADDR4_INIT(PP_HTONL(IPADDR_LOOPBACK))
#else
#define LWIP_MQTT_EXAMPLE_IPADDR_INIT
#endif
#endif

static ip_addr_t mqtt_ip LWIP_MQTT_EXAMPLE_IPADDR_INIT;
static mqtt_client_t* mqtt_client;

static const struct mqtt_connect_client_info_t mqtt_client_info =
{
  "test",
  DEFAULT_MQTT_USER, /* user */
  DEFAULT_MQTT_PASS, /* pass */
  100,  /* keep alive */
  NULL, /* will_topic */
  NULL, /* will_msg */
  0,    /* will_qos */
  0     /* will_retain */
#if LWIP_ALTCP && LWIP_ALTCP_TLS
  , NULL
#endif
};


/* Called when publish is complete either with sucess or failure */
static void mqtt_pub_request_cb(void *arg, err_t result)
{
  if(result != ERR_OK) {
    bk_printf("Publish result: %d\n", result);
  }
}
static void
mqtt_connection_cb(mqtt_client_t *client, void *arg, mqtt_connection_status_t status);
void mqtt_example_init(void);
void example_publish(mqtt_client_t *client, int channel, int iVal)
{
	char pub_topic[32];
	char pub_payload[128];
//  const char *pub_payload= "{\"temperature\": \"45.5\"}";
  err_t err;
  int myValue;
  u8_t qos = 2; /* 0 1 or 2, see MQTT specification */
  u8_t retain = 0; /* No don't retain such crappy payload... */
  
  if(client==0)
	  return;
  if(mqtt_client_is_connected(client)==0) {
		 g_my_reconnect_mqtt_after_time = 5;
		return;
  }

  myValue = CHANNEL_Check(channel);
   sprintf(pub_payload,"%i",myValue);
   
    bk_printf("calling pub: \n");
	sprintf(pub_topic,"wb2s/%i/get",channel);
  err = mqtt_publish(client, pub_topic, pub_payload, strlen(pub_payload), qos, retain, mqtt_pub_request_cb, 0);
  if(err != ERR_OK) {
    bk_printf("Publish err: %d\n", err);
	 if(err == ERR_CONN) {
		 
		// g_my_reconnect_mqtt_after_time = 5;

       // mqtt_example_init();

  //mqtt_client_connect(mqtt_client,
    //      &mqtt_ip, MQTT_PORT,
    //      mqtt_connection_cb, LWIP_CONST_CAST(void*, &mqtt_client_info),
     //     &mqtt_client_info);
	 }
  }
}

int g_incoming_channel_mqtt = 0;
static void mqtt_incoming_data_cb(void *arg, const u8_t *data, u16_t len, u8_t flags)
{
	int iValue;
  const struct mqtt_connect_client_info_t* client_info = (const struct mqtt_connect_client_info_t*)arg;
  //bk_printf("MQTT client in mqtt_incoming_data_cb\n");
  bk_printf("MQTT client in mqtt_incoming_data_cb data is %s for ch %i\n",data,g_incoming_channel_mqtt);

  iValue = atoi(data);
  CHANNEL_Set(g_incoming_channel_mqtt,iValue);

 // bk_printf(("MQTT client \"%s\" data cb: len %d, flags %d\n", client_info->client_id, (int)len, (int)flags));
}

static void mqtt_incoming_publish_cb(void *arg, const char *topic, u32_t tot_len)
{
  const struct mqtt_connect_client_info_t* client_info = (const struct mqtt_connect_client_info_t*)arg;
  //bk_printf("MQTT client in mqtt_incoming_publish_cb\n");
  bk_printf("MQTT client in mqtt_incoming_publish_cb topic %s\n",topic);
// TODO: better
  g_incoming_channel_mqtt = topic[5] - '0';
 // bk_printf(("MQTT client \"%s\" publish cb: topic %s, len %d\n", client_info->client_id, topic, (int)tot_len));
}

static void
mqtt_request_cb(void *arg, err_t err)
{
  const struct mqtt_connect_client_info_t* client_info = (const struct mqtt_connect_client_info_t*)arg;

  bk_printf("MQTT client \"%s\" request cb: err %d\n", client_info->client_id, (int)err);
}
static void mqtt_sub_request_cb(void *arg, err_t result)
{
  /* Just print the result code here for simplicity,
     normal behaviour would be to take some action if subscribe fails like
     notifying user, retry subscribe or disconnect from server */
  bk_printf("Subscribe result: %i\n", result);
}
void example_do_connect(mqtt_client_t *client);
static void mqtt_connection_cb(mqtt_client_t *client, void *arg, mqtt_connection_status_t status)
{
	int i;
	char tmp[32];
  err_t err = ERR_OK;
  const struct mqtt_connect_client_info_t* client_info = (const struct mqtt_connect_client_info_t*)arg;
  LWIP_UNUSED_ARG(client);

//  bk_printf(("MQTT client < removed name > connection cb: status %d\n",  (int)status));
 // bk_printf(("MQTT client \"%s\" connection cb: status %d\n", client_info->client_id, (int)status));

  if (status == MQTT_CONNECT_ACCEPTED) {
    bk_printf("mqtt_connection_cb: Successfully connected\n");


  mqtt_set_inpub_callback(mqtt_client,
          mqtt_incoming_publish_cb,
          mqtt_incoming_data_cb,
          LWIP_CONST_CAST(void*, &mqtt_client_info));

	 /* Subscribe to a topic named "subtopic" with QoS level 1, call mqtt_sub_request_cb with result */


  // + is a MQTT wildcard
    err = mqtt_sub_unsub(client,
            "wb2s/+/set", 1,
            mqtt_request_cb, LWIP_CONST_CAST(void*, client_info),
            1);
    if(err != ERR_OK) {
      bk_printf("mqtt_subscribe return: %d\n", err);
    }


    //mqtt_sub_unsub(client,
    //        "topic_qos1", 1,
    //        mqtt_request_cb, LWIP_CONST_CAST(void*, client_info),
    //        1);
    //mqtt_sub_unsub(client,
    //        "topic_qos0", 0,
    //        mqtt_request_cb, LWIP_CONST_CAST(void*, client_info),
    //        1);
  } else {
    bk_printf("mqtt_connection_cb: Disconnected, reason: %d\n", status);
    example_do_connect(client);

  }
}

void example_do_connect(mqtt_client_t *client)
{
  err_t err;

  	ipaddr_aton(DEFAULT_MQTT_IP,&mqtt_ip);

  /* Initiate client and connect to server, if this fails immediately an error code is returned
     otherwise mqtt_connection_cb will be called with connection result after attempting
     to establish a connection with the server.
     For now MQTT version 3.1.1 is always used */

  mqtt_client_connect(mqtt_client,
          &mqtt_ip, MQTT_PORT,
          mqtt_connection_cb, LWIP_CONST_CAST(void*, &mqtt_client_info),
          &mqtt_client_info);


  /* For now just print the result code if something goes wrong */
  if(err != ERR_OK) {
    bk_printf("mqtt_connect return %d\n", err);
  }
}


void mqtt_example_init(void)
{
  mqtt_client = mqtt_client_new();

	

	example_do_connect(mqtt_client);
}

static void app_my_channel_toggle_callback(int channel, int iVal)
{
    bk_printf("Channel has changed! Publishing change %i with %i \n",channel,iVal);
	example_publish(mqtt_client,channel,iVal);
}

#define HTTPCLIENTTEST

#ifdef HTTPCLIENTTEST

httprequest_t httprequest;
int total_bytes = 0;

int myhttpclientcallback(httprequest_t* request){

  httpclient_t *client = &request->client;
  httpclient_data_t *client_data = &request->client_data;

  // NOTE: Called from the client thread, beware
  total_bytes += request->client_data.response_buf_filled;

  switch(request->state){
    case 0: // start
      //init_ota(0xff000);
      init_ota(0x132000);
      addLog("\r\nmyhttpclientcallback state %d total %d/%d\r\n", request->state, total_bytes, request->client_data.response_content_len);
      break;
    case 1: // data
      if (request->client_data.response_buf_filled){
        unsigned char *d = request->client_data.response_buf;
        int l = request->client_data.response_buf_filled;
        add_otadata(d, l);
      }
      break;
    case 2: // ended, write any remaining bytes to the sector
      close_ota();
      addLog("\r\nmyhttpclientcallback state %d total %d/%d\r\n", request->state, total_bytes, request->client_data.response_content_len);
      break;
  }

  //rtos_delay_milliseconds(500);

  if (request->state == 2){
    //os_free(client_data->response_buf);
    client_data->response_buf = (void*)0;
    client_data->response_buf_len = 0;
  }
  //rtos_delay_milliseconds(100);

  return 0;
}

  // NOTE: these MUST persist
// note: url must have a '/' after host, else it can;t parse it.. 
char *url = "http://raspberrypi/firmware";
char *header = "";//"deviceKey:FZoo0S07CpwUHcrt\r\n";
char *content_type = "text/csv";
char *post_data = "1,,I am string!";
#define BUF_SIZE 1024

char *http_buf = (void *)0;

void startrequest(){
  httprequest_t *request = &httprequest;
  if (request->state == 1){
    addLog("********************http in progress, not starting another\r\n");
    return;
  }

  total_bytes = 0;
  memset(request, 0, sizeof(*request));
  httpclient_t *client = &request->client;
  httpclient_data_t *client_data = &request->client_data;

  if (http_buf == NULL){
    http_buf = os_malloc(BUF_SIZE+1); 
    if (http_buf == NULL) {
        addLog("startrequest Malloc failed.\r\n");
        return;
    }
    memset(http_buf, 0, BUF_SIZE);
  }
  client_data->response_buf = http_buf;  //Sets a buffer to store the result.
  client_data->response_buf_len = BUF_SIZE;  //Sets the buffer size.
  httpclient_set_custom_header(&client, header);  //Sets the custom header if needed.
  client_data->post_buf = post_data;  //Sets the user data to be posted.
  client_data->post_buf_len = strlen(post_data);  //Sets the post data length.
  client_data->post_content_type = content_type;  //Sets the content type.
  request->data_callback = &myhttpclientcallback; 
  request->port = 1880;//HTTP_PORT;
  request->url = url;
  request->method = HTTPCLIENT_GET; 
  request->timeout = 10000;
  async_request(request);
 }
#endif

int loopsWithDisconnected = 0;
#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x "

static void app_led_timer_handler(void *data)
{
	if(mqtt_client != 0 && mqtt_client_is_connected(mqtt_client) == 0) {
		bk_printf("Timer discovetrs disconnected mqtt %i\n",loopsWithDisconnected);
		loopsWithDisconnected++;
		if(loopsWithDisconnected>10){ 
			example_do_connect(mqtt_client);
			loopsWithDisconnected = 0;
		}
	}

	cnt ++;

#ifdef HTTPCLIENTTEST
  if (cnt == 25){
    startrequest();
  }
#endif


    // print IP info
    {
      IPStatusTypedef ipStatus;

      os_memset(&ipStatus, 0x0, sizeof(IPStatusTypedef));
      bk_wlan_get_ip_status(&ipStatus, STATION);
        
      char *fmt = "dhcp=%d ip=%s gate=%s mask=%s mac=" MACSTR "\r\n";
      bk_printf(fmt ,
            ipStatus.dhcp, ipStatus.ip, ipStatus.gate, 
            ipStatus.mask, MAC2STR((unsigned char*)ipStatus.mac));

    }
    // print wifi state
    {
    	LinkStatusTypeDef linkStatus;
      network_InitTypeDef_ap_st ap_info;
      char ssid[33] = {0};
      #if CFG_IEEE80211N
          bk_printf("sta: %d, softap: %d, b/g/n\r\n",sta_ip_is_start(),uap_ip_is_start());
      #else
          bk_printf("sta: %d, softap: %d, b/g\r\n",sta_ip_is_start(),uap_ip_is_start());
      #endif
      
      if( sta_ip_is_start() )
      {
        os_memset(&linkStatus, 0x0, sizeof(LinkStatusTypeDef));
        bk_wlan_get_link_status(&linkStatus);
          os_memcpy(ssid, linkStatus.ssid, 32);

        char *fmt = "sta:rssi=%d,ssid=%s,bssid=" MACSTR ",channel=%d,cipher_type:";
        bk_printf(fmt,
          linkStatus.wifi_strength, ssid, MAC2STR(linkStatus.bssid), linkStatus.channel);
          switch(bk_sta_cipher_type())
          {
            case SECURITY_TYPE_NONE:
                  bk_printf("OPEN\r\n");
                  break;
              case SECURITY_TYPE_WEP :
                  bk_printf("WEP\r\n");
                  break;
              case SECURITY_TYPE_WPA_TKIP:
                  bk_printf("TKIP\r\n");
                  break;
              case SECURITY_TYPE_WPA2_AES:
                  bk_printf("CCMP\r\n");
                  break;
              case SECURITY_TYPE_WPA2_MIXED:
                  bk_printf("MIXED\r\n");
                  break;
              case SECURITY_TYPE_AUTO:
                  bk_printf("AUTO\r\n");
                  break;
              default:
                  bk_printf("Error\r\n");
                  break;
          }
      }
      
      if( uap_ip_is_start() )
      {
        os_memset(&ap_info, 0x0, sizeof(network_InitTypeDef_ap_st));
        bk_wlan_ap_para_info_get(&ap_info);
          os_memcpy(ssid, ap_info.wifi_ssid, 32);
          bk_printf("softap:ssid=%s,channel=%d,dhcp=%d,cipher_type:",
          ssid, ap_info.channel,ap_info.dhcp_mode);
          switch(ap_info.security)
          {
            case SECURITY_TYPE_NONE:
                  bk_printf("OPEN\r\n");
                  break;
              case SECURITY_TYPE_WEP :
                  bk_printf("WEP\r\n");
                  break;
              case SECURITY_TYPE_WPA_TKIP:
                  bk_printf("TKIP\r\n");
                  break;
              case SECURITY_TYPE_WPA2_AES:
                  bk_printf("CCMP\r\n");
                  break;
              case SECURITY_TYPE_WPA2_MIXED:
                  bk_printf("MIXED\r\n");
                  break;
              case SECURITY_TYPE_AUTO:
                  bk_printf("AUTO\r\n");
                  break;
              default:
                  bk_printf("Error\r\n");
                  break;
          }
          bk_printf("ip=%s,gate=%s,mask=%s,dns=%s\r\n",
          ap_info.local_ip_addr, ap_info.gateway_ip_addr, ap_info.net_mask, ap_info.dns_server_ip_addr);
      }

    }


    if (reconnect){
      reconnect--;
      bk_printf("*****reconnect %d", reconnect);
      switch(reconnect){
          case 1:
              bk_wlan_stop(STATION);
              break;
          case 0:
            	connect_to_wifi(DEFAULT_WIFI_SSID,DEFAULT_WIFI_PASS);
              break;
      }
    }


    bk_printf("Timer is %i free mem %d\r\n", cnt, xPortGetFreeHeapSize());
}

void myInit()
{

    OSStatus err;
	
#if 1
	PIN_Init();
#endif

#if 1
	CHANNEL_SetChangeCallback(app_my_channel_toggle_callback);
#endif

    err = rtos_init_timer(&led_timer,
                          1 * 1000,
                          app_led_timer_handler,
                          (void *)0);
    ASSERT(kNoErr == err);

    err = rtos_start_timer(&led_timer);
    ASSERT(kNoErr == err);
}


/* Private functions ---------------------------------------------------------*/
/**
 * @Function: wifi_state_led_reminder
 * @Description: WiFi led指示灯，根据当前 WiFi 状态，做出不同提示 
 * @Input: cur_stat：当前 WiFi 状态 
 * @Output: none
 * @Return: none
 * @Others: 
 */
STATIC VOID wifi_state_led_reminder(IN CONST GW_WIFI_NW_STAT_E cur_stat)
{
   
}

/**
 * @Function: wifi_key_process
 * @Description: 按键回调函数
 * @Input: port：触发引脚,type：按键触发类型,cnt:触发次数
 * @Output: none
 * @Return: none
 * @Others: 长按触发配网模式
 */
STATIC VOID wifi_key_process(TY_GPIO_PORT_E port,PUSH_KEY_TYPE_E type,INT_T cnt)
{


    return;
}

/**
 * @Function: wifi_config_init
 * @Description: 初始化 WiFi 相关设备，按键，led指示灯
 * @Input: none
 * @Output: none
 * @Return: none
 * @Others: 
 */
STATIC VOID wifi_config_init(VOID)
{
 

    return;
}

/**
 * @Function: hw_report_all_dp_status
 * @Description: 上报所有 dp 点
 * @Input: none
 * @Output: none
 * @Return: none
 * @Others: 
 */
VOID hw_report_all_dp_status(VOID)
{
    //report all dp status
}

/**
 * @Function:gpio_test 
 * @Description: gpio测试
 * @Input: none
 * @Output: none
 * @Return: none
 * @Others: none
 */
BOOL_T gpio_test(IN CONST CHAR_T *in, OUT CHAR_T *out)
{
    return gpio_test_all(in, out);
}

/**
 * @Function: mf_user_callback
 * @Description: 授权回调函数
 * @Input: none
 * @Output: none
 * @Return: none
 * @Others: 清空flash中存储的数据
 */
VOID mf_user_callback(VOID)
{
    hw_reset_flash_data();
    return;
}

/**
 * @Function: prod_test
 * @Description: 扫描到产测热点，进入回调函数，主要是按键、指示灯、继电器功能测试
 * @Input: flag:授权标识；rssi:信号强度
 * @Output: none
 * @Return: none
 * @Others: none
 */
VOID prod_test(BOOL_T flag, SCHAR_T rssi)
{
    if (flag == FALSE || rssi < -60) 
    {
        PR_ERR("Prod test failed... flag:%d, rssi:%d", flag, rssi);
        return;
    }
    bk_printf("flag:%d rssi:%d", flag, rssi);

}

/**
 * @Function: app_init
 * @Description: 设备初始化，设置工作模式
 * @Input: none
 * @Output: none
 * @Return: none
 * @Others: 无
 */
// NOTE: this is externally called from tuya_mainc
//VOID app_init(VOID)
//{

//}

/**
 * @Function: pre_device_init
 * @Description: 设备信息(SDK信息、版本号、固件标识等)打印、重启原因和打印等级设置
 * @Input: none
 * @Output: none
 * @Return: none
 * @Others: none
 */
VOID pre_device_init(VOID)
{
    bk_printf("%s",tuya_iot_get_sdk_info());
    //bk_printf("%s:%s",APP_BIN_NAME,DEV_SW_VERSION);
    bk_printf("firmware compiled at %s %s", __DATE__, __TIME__);
    bk_printf("Hello Tuya World!");
    bk_printf("system reset reason:[%s]",tuya_hal_system_get_rst_info());
    /* 打印等级设置 */
    SetLogManageAttr(TY_LOG_LEVEL_DEBUG);
}

/**
 * @Function: status_changed_cb
 * @Description: network status changed callback
 * @Input: status: current status
 * @Output: none
 * @Return: none
 * @Others: none
 */
VOID status_changed_cb(IN CONST GW_STATUS_E status)
{

}

/**
 * @Function: upgrade_notify_cb
 * @Description: firmware download finish result callback
 * @Input: fw: firmware info
 * @Input: download_result: 0 means download succes. other means fail
 * @Input: pri_data: private data
 * @Output: none
 * @Return: none
 * @Others: none
 */
VOID upgrade_notify_cb(IN CONST FW_UG_S *fw, IN CONST INT_T download_result, IN PVOID_T pri_data)
{

}

/**
 * @Function: get_file_data_cb
 * @Description: firmware download content process callback
 * @Input: fw: firmware info
 * @Input: total_len: firmware total size
 * @Input: offset: offset of this download package
 * @Input: data && len: this download package
 * @Input: pri_data: private data
 * @Output: remain_len: the size left to process in next cb
 * @Return: OPRT_OK: success  Other: fail
 * @Others: none
 */
OPERATE_RET get_file_data_cb(IN CONST FW_UG_S *fw, IN CONST UINT_T total_len, IN CONST UINT_T offset, \
                                     IN CONST BYTE_T *data, IN CONST UINT_T len, OUT UINT_T *remain_len, IN PVOID_T pri_data)
{

    return OPRT_OK;
}

/**
 * @Function: gw_ug_inform_cb
 * @Description: gateway ota firmware available nofity callback
 * @Input: fw: firmware info
 * @Output: none
 * @Return: int:
 * @Others: 
 */
INT_T gw_ug_inform_cb(IN CONST FW_UG_S *fw)
{

    return 0;
}

/**
 * @Function: hw_reset_flash_data
 * @Description: hardware reset, erase user data from flash
 * @Input: none
 * @Output: none
 * @Return: none
 * @Others: 
 */
VOID hw_reset_flash_data(VOID)
{
    return;
}

/**
 * @Function: gw_reset_cb
 * @Description: gateway restart callback, app remove the device 
 * @Input: type:gateway reset type
 * @Output: none
 * @Return: none
 * @Others: reset factory clear flash data
 */
VOID gw_reset_cb(IN CONST GW_RESET_TYPE_E type)
{

}

/**
 * @Function: dev_obj_dp_cb
 * @Description: obj dp info cmd callback, tuya cloud dp(data point) received
 * @Input: dp:obj dp info
 * @Output: none
 * @Return: none
 * @Others: app send data by dpid  control device stat
 */
VOID dev_obj_dp_cb(IN CONST TY_RECV_OBJ_DP_S *dp)
{

}

/**
 * @Function: dev_raw_dp_cb
 * @Description: raw dp info cmd callback, tuya cloud dp(data point) received (hex data)
 * @Input: dp: raw dp info
 * @Output: none
 * @Return: none
 * @Others: none
 */
VOID dev_raw_dp_cb(IN CONST TY_RECV_RAW_DP_S *dp)
{

    return;
}

/**
 * @Function: dev_dp_query_cb
 * @Description: dp info query callback, cloud or app actively query device info
 * @Input: dp_qry: query info
 * @Output: none
 * @Return: none
 * @Others: none
 */
STATIC VOID dev_dp_query_cb(IN CONST TY_DP_QUERY_S *dp_qry) 
{

}

/**
 * @Function: wf_nw_status_cb
 * @Description: tuya-sdk network state check callback
 * @Input: stat: curr network status
 * @Output: none
 * @Return: none
 * @Others: none
 */
VOID wf_nw_status_cb(IN CONST GW_WIFI_NW_STAT_E stat)
{

}

static void setup_deviceNameUnique()
{
	u8 mac[32];
    wifi_get_mac_address(mac, CONFIG_ROLE_STA);
	sprintf(g_deviceName,"OpenBK7231T_%02X%02X%02X%02X",mac[0],mac[1],mac[2],mac[3]);
	sprintf(g_shortDeviceName,"obk%02X%02X%02X%02X",mac[0],mac[1],mac[2],mac[3]);

		// NOT WORKING, I done it other way, see ethernetif.c
	//net_dhcp_hostname_set(g_shortDeviceName);
}

static int setup_wifi_open_access_point(void)
{
    //#define APP_DRONE_DEF_SSID          "WIFI_UPV_000000"
    #define APP_DRONE_DEF_NET_IP        "192.168.4.151"
    #define APP_DRONE_DEF_NET_MASK      "255.255.255.0"
    #define APP_DRONE_DEF_NET_GW        "192.168.4.151"
    #define APP_DRONE_DEF_CHANNEL       1    
    
    general_param_t general;
    ap_param_t ap_info;
    network_InitTypeDef_st wNetConfig;
    int len;
    u8 *mac;
    
    os_memset(&general, 0, sizeof(general_param_t));
    os_memset(&ap_info, 0, sizeof(ap_param_t)); 
    os_memset(&wNetConfig, 0x0, sizeof(network_InitTypeDef_st));  
    
        general.role = 1,
        general.dhcp_enable = 1,

        os_strcpy((char *)wNetConfig.local_ip_addr, APP_DRONE_DEF_NET_IP);
        os_strcpy((char *)wNetConfig.net_mask, APP_DRONE_DEF_NET_MASK);
        os_strcpy((char *)wNetConfig.dns_server_ip_addr, APP_DRONE_DEF_NET_GW);
 

        bk_printf("no flash configuration, use default\r\n");
        mac = (u8*)&ap_info.bssid.array;
		// this is MAC for Access Point, it's different than Client one
		// see wifi_get_mac_address source
        wifi_get_mac_address(mac, CONFIG_ROLE_AP);
        ap_info.chann = APP_DRONE_DEF_CHANNEL;
        ap_info.cipher_suite = 0;
        //os_memcpy(ap_info.ssid.array, APP_DRONE_DEF_SSID, os_strlen(APP_DRONE_DEF_SSID));
        os_memcpy(ap_info.ssid.array, g_deviceName, os_strlen(g_deviceName));
		
        ap_info.key_len = 0;
        os_memset(&ap_info.key, 0, 65);   
  

    bk_wlan_ap_set_default_channel(ap_info.chann);

    len = os_strlen(ap_info.ssid.array);

    os_strcpy((char *)wNetConfig.wifi_ssid, ap_info.ssid.array);
    os_strcpy((char *)wNetConfig.wifi_key, ap_info.key);
    
    wNetConfig.wifi_mode = SOFT_AP;
    wNetConfig.dhcp_mode = DHCP_SERVER;
    wNetConfig.wifi_retry_interval = 100;
    
    bk_printf("set ip info: %s,%s,%s\r\n",
            wNetConfig.local_ip_addr,
            wNetConfig.net_mask,
            wNetConfig.dns_server_ip_addr);
    
    bk_printf("ssid:%s  key:%s\r\n", wNetConfig.wifi_ssid, wNetConfig.wifi_key);
	bk_wlan_start(&wNetConfig);

    return 0;    
}


/**
 * @Function: device_init
 * @Description: device initialization process 
 * @Input: none
 * @Output: none
 * @Return: OPRT_OK: success  Other: fail
 * @Others: none
 */



//ctxt is pointer to a rw_evt_type
void wl_status( void *ctxt ){

    rw_evt_type stat = *((rw_evt_type*)ctxt);
	bk_printf("wl_status %d\r\n", stat);

    switch(stat){
        case RW_EVT_STA_IDLE:
        case RW_EVT_STA_SCANNING:
        case RW_EVT_STA_SCAN_OVER:
        case RW_EVT_STA_CONNECTING:
            break;
        case RW_EVT_STA_BEACON_LOSE:
        case RW_EVT_STA_PASSWORD_WRONG:
        case RW_EVT_STA_NO_AP_FOUND:
        case RW_EVT_STA_ASSOC_FULL:
        case RW_EVT_STA_DISCONNECTED:    /* disconnect with server */
            // try to connect again in 5 seconds
            reconnect = 5;
            break;
        case RW_EVT_STA_CONNECT_FAILED:  /* authentication failed */
        case RW_EVT_STA_CONNECTED:	    /* authentication success */	
            break;
        case RW_EVT_STA_GOT_IP: 
          	//demo_start_tcp();
            break;

        /* for softap mode */
        case RW_EVT_AP_CONNECTED:          /* a client association success */
        case RW_EVT_AP_DISCONNECTED:       /* a client disconnect */
        case RW_EVT_AP_CONNECT_FAILED:     /* a client association failed */
        default:
            break;
    }

}


void app_init(VOID)
//OPERATE_RET device_init(VOID)
{
    OPERATE_RET op_ret = OPRT_OK;

	myInit();

  // this may be killing it?
	//setup_deviceNameUnique();


	connect_to_wifi(DEFAULT_WIFI_SSID,DEFAULT_WIFI_PASS);
  bk_wlan_status_register_cb(wl_status);
	//setup_wifi_open_access_point();

		// NOT WORKING, I done it other way, see ethernetif.c
	//net_dhcp_hostname_set(g_shortDeviceName);

	//demo_start_upd();
#if 1
	demo_start_tcp();
#endif
#if 0
	PIN_LoadFromFlash();
#else

#endif

#if 0
  init_ota(0x120000);
  add_otadata((unsigned char *)"hello", 5);
  add_otadata((unsigned char *)" hello2", 7);
  close_ota();
#endif

#if 0
	mqtt_example_init();
#endif

  //return op_ret;
}
