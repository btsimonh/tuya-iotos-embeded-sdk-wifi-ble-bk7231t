/* Includes ------------------------------------------------------------------*/
#include "uni_log.h"
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
#include "utils_httpc.h"

#include "lwip/sockets.h"
#include "lwip/ip_addr.h"
#include "lwip/inet.h"
#include "lwip/apps/mqtt.h"

/* Private includes ----------------------------------------------------------*/

#define PrintLog bk_printf

beken_timer_t stat_timer;
static mqtt_client_t* mqtt_client;

void connect_to_wifi(const char *oob_ssid,const char *connect_key);
void _app_init(void);
void StartUpgrade();


#define SERVER_PORT            20000 /*set up a tcp server,port at 20000*/
int my_fd = -1; 
#define tcp_server_log(M, ...) os_printf("TCP", M, ##__VA_ARGS__)


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
    os_printf("select ret:%d, %d, %d\r\n", ret, FD_ISSET( fd, &readfds ), FD_ISSET( fd, &errfds ));

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
    int totallen = 0;
    fd_set readfds, errfds, readfds2; 
    char *buf = NULL;

    my_fd = fd;

    buf = (char*) os_malloc( 1024 );
    ASSERT(buf);
	bk_printf( "TCP client thread start" );

    // DO NOT Try this without further investigation - this bricked my unit
    //http_flash_init();


    while ( 1 )
    {
           
        {
            len = recv( fd, buf, 1024, 0 );
            totallen += len;

            if ( len <= 0 )
            {
                bk_printf( "TCP Client is disconnected, fd: %d", fd );
                goto exit;
            }
            // DO NOT Try this without further investigation - this bricked my unit
            //http_wr_to_flash(buf, len);

            //PR_NOTICE( "TCP received string %s\n",buf );

			//len = strlen(buf);
            // example of sending - works.
            //len = send( fd, buf, len, 0 );
            //bk_printf(buf);

            rtos_delay_milliseconds(10);
        }
    }
	
exit:
    if ( err != kNoErr ) 
		bk_printf( "TCP client thread exit with err: %d", err );
	
    if ( buf != NULL ) 
		os_free( buf );
	
    close( fd );
	bk_printf("[would have flashed %d]", totallen);

    // DO NOT Try this without further investigation - this bricked my unit
    //http_flash_deinit();

    rtos_delete_thread( NULL );
}

volatile u8 test_flag = 0;
void close_tcp_client(void)
{
    os_printf("close_tcp_client:%d, %p\r\n", my_fd, rtos_get_current_thread());
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
    server_addr.sin_port = htons( SERVER_PORT );/* Server listen on port: 20000 */
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
       os_printf("create \"TCP_server\" thread failed!\r\n");
    }
}


int count = 0;
int reconnect = 0;
static void app_stat_timer_handler(void *data)
{
    //bk_printf("IP %d.%d.%d.%d\n\r",wireless_ip[0], wireless_ip[1], wireless_ip[2], wireless_ip[3]); 
    bk_printf("count %d", count++);

    // print IP info
    demo_ip_app_init();
    // print wifi state
    demo_state_app_init();

    if (count == 10){
        // look for ap
        demo_scan_app_init();
    }

    if (!(count % 5)){
        example_publish(mqtt_client,0);
    }


    if (count == 15){
        StartUpgrade();
    }


    if (reconnect){
        reconnect--;
        bk_printf("*****reconnect %d", reconnect);
        switch(reconnect){
            case 1:
                bk_wlan_stop(STATION);
                break;
            case 0:
                connect_to_wifi("SOMESSID", "SOMEPASSWORD");
                break;
        }
    }

}


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
        case RW_EVT_STA_GOT_IP: 
        
        /* for softap mode */
        case RW_EVT_AP_CONNECTED:          /* a client association success */
        case RW_EVT_AP_DISCONNECTED:       /* a client disconnect */
        case RW_EVT_AP_CONNECT_FAILED:     /* a client association failed */
        default:
            break;
    }

}


/***********************************************************
*  Function: app_init 
*  Input: none
*  Output: none
*  Return: none
***********************************************************/
void app_init(void)
{
    OSStatus err;
    err = rtos_init_timer(&stat_timer,
                          5 * 1000,
                          app_stat_timer_handler,
                          (void *)0);
    ASSERT(kNoErr == err);

    err = rtos_start_timer(&stat_timer);
    ASSERT(kNoErr == err);

    connect_to_wifi("SOMESSID", "SOMEPASSWORD");

    bk_wlan_status_register_cb(wl_status);

    httpd_init();

    mqtt_example_init();

    demo_start_tcp();
}

void connect_to_wifi(const char *oob_ssid,const char *connect_key)
{
    demo_sta_adv_app_init(oob_ssid, connect_key);
}


#define HTTP_RESP_CONTENT_LEN   (256)
void http_client_Command(char *pcWriteBuffer, int xWriteBufferLen, int argc, char **argv)
{
    int ret;
    httpclient_t httpclient;
    httpclient_data_t httpclient_data;
    char http_content[HTTP_RESP_CONTENT_LEN];

    if ( argc != 2 )
    {
        goto HTTP_CMD_ERR;
    }    
    os_memset(&httpclient, 0, sizeof(httpclient_t));
    os_memset(&httpclient_data, 0, sizeof(httpclient_data));
    os_memset(&http_content, 0, sizeof(HTTP_RESP_CONTENT_LEN));
    httpclient.header = "Accept: text/xml,text/html,\r\n"; 
    httpclient_data.response_buf = http_content; 
    httpclient_data.response_content_len = HTTP_RESP_CONTENT_LEN;
    ret = httpclient_common(&httpclient,
        argv[1],  
        1880,  
        NULL,
        HTTPCLIENT_GET, 
        5000,
        &httpclient_data); 
    if (0 != ret) { 
        bk_printf("request epoch time from remote server failed.");
        } else {  
        bk_printf("sucess.\r\n");
    }

    return;
HTTP_CMD_ERR:
    bk_printf("Usage:httpc [url:]\r\n");
        
}


void StartUpgrade(){
    char *argv[] = {
        "httpc",
        "http://192.168.1.40"
    };
    int argc = 2;
    bk_printf("*****start upgrade %s\r\n", argv[0]);
    http_client_Command("", 0, argc, argv);

}

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
  "raspberrypi",
  "admin", /* user */
  "password", /* pass */
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

void mqtt_example_init(void);
void example_publish(mqtt_client_t *client, void *arg)
{
    static int cnt = 0;
    cnt++;
	char pub_payload[128];
//  const char *pub_payload= "{\"temperature\": \"45.5\"}";
  err_t err;
  u8_t qos = 2; /* 0 1 or 2, see MQTT specification */
  u8_t retain = 0; /* No don't retain such crappy payload... */
  
  if(client==0)
	  return;
   sprintf(pub_payload,"{\"temperature\": \"%i\"}",(int)(20+20*sin(cnt*0.01f)));
   
    bk_printf("calling pub: \n");
  err = mqtt_publish(client, "wb2s", pub_payload, strlen(pub_payload), qos, retain, mqtt_pub_request_cb, arg);
  if(err != ERR_OK) {
    bk_printf("Publish err: %d\n", err);
	 if(err == ERR_CONN) {
		 
        mqtt_example_init();
	 }
  }
}

static void
mqtt_incoming_data_cb(void *arg, const u8_t *data, u16_t len, u8_t flags)
{
    bk_printf("%%%%%% data_cb %%%%%%\r\n");
    return;
  const struct mqtt_connect_client_info_t* client_info = (const struct mqtt_connect_client_info_t*)arg;
  LWIP_UNUSED_ARG(data);

  bk_printf("MQTT client \"%s\" data cb: len %d, flags %d\n", client_info->client_id,
          (int)len, (int)flags);
}

static void
mqtt_incoming_publish_cb(void *arg, const char *topic, u32_t tot_len)
{
    bk_printf("%%%%%% publish_cb %%%%%%\r\n");
    return;
  const struct mqtt_connect_client_info_t* client_info = (const struct mqtt_connect_client_info_t*)arg;

  bk_printf("MQTT client \"%s\" publish cb: topic %s, len %d\n", client_info->client_id,
          topic, (int)tot_len);
}

static void
mqtt_request_cb(void *arg, err_t err)
{
  const struct mqtt_connect_client_info_t* client_info = (const struct mqtt_connect_client_info_t*)arg;

  bk_printf("MQTT client \"%s\" request cb: err %d\n", client_info->client_id, (int)err);
}

static void
mqtt_connection_cb(mqtt_client_t *client, void *arg, mqtt_connection_status_t status)
{
  const struct mqtt_connect_client_info_t* client_info = (const struct mqtt_connect_client_info_t*)arg;
  LWIP_UNUSED_ARG(client);

  bk_printf("MQTT client \"%s\" connection cb: status %d\n", client_info->client_id, (int)status);

  if (status == MQTT_CONNECT_ACCEPTED) {
    mqtt_sub_unsub(client,
            "subtopic", 0,
            mqtt_request_cb, LWIP_CONST_CAST(void*, client_info),
            1);
  }
}

void mqtt_example_init(void)
{
  mqtt_client = mqtt_client_new();

	ipaddr_aton("192.168.1.40",&mqtt_ip);
	//ipaddr_aton("192.168.0.110",&mqtt_ip);
	//ipaddr_aton("192.168.0.114",&mqtt_ip);
	
  mqtt_set_inpub_callback(mqtt_client,
          mqtt_incoming_publish_cb,
          mqtt_incoming_data_cb,
          LWIP_CONST_CAST(void*, &mqtt_client_info));

  mqtt_client_connect(mqtt_client,
          &mqtt_ip, MQTT_PORT,
          mqtt_connection_cb, LWIP_CONST_CAST(void*, &mqtt_client_info),
          &mqtt_client_info);
}




