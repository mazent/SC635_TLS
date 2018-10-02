#include "bsp.h"
#include "ap.h"
#include "tlssrv.h"

#include "nvs_flash.h"
#include "esp_event_loop.h"
#include "esp_event.h"


#include "versione.h"


#ifdef NDEBUG
const uint32_t VERSIONE = (1 << 24) + VER ;
#else
const uint32_t VERSIONE = VER ;
#endif
const char * DATA = __DATE__ ;

static const char * TAG = "tls";

static const char CLN_CN[] = "utente SC635" ;

static const char CERT_CHAIN[] = {
	// intermediate CA
	"-----BEGIN CERTIFICATE-----\r\n"
	"MIIFLjCCAxagAwIBAgIRAK3bnKXNe5ENrV3HeRgf3uQwDQYJKoZIhvcNAQELBQAw\r\n"
	"NDELMAkGA1UEBhMCSVQxEDAOBgNVBAoMB1RleGEgR0UxEzARBgNVBAMMClVmZmlj\r\n"
	"aW8gRlcwHhcNMTgwOTIxMDg0MjQyWhcNMzgwOTIxMDg0MjQyWjBYMQswCQYDVQQG\r\n"
	"EwJJVDEQMA4GA1UECgwHVGV4YSBHRTEiMCAGA1UEAwwZMjA4IC0gQWRhdHRhdG9y\r\n"
	"ZSBEb0lQIE9CRDETMBEGA1UECwwKVWZmaWNpbyBGVzCCASIwDQYJKoZIhvcNAQEB\r\n"
	"BQADggEPADCCAQoCggEBAOwaNcHzImJjoc+awzbkgWrO3a32GWpPHk1cOOmYgiB3\r\n"
	"cOc9lwYU0nwORuIVptmsE4y8mp7al8GE41Xpgs33tCH5thsSWFQACNa0gn06+DnJ\r\n"
	"dvCqx0pISEFSaMrRDW/83pKUk+pHdA3qqIAzWIuSBhvZLr4fqpOj6O70EscwriGc\r\n"
	"JieAx12EzM2rqg7A3e26+/onz5jdzmk2N28UdTLVco949uzNKpWtgIXnycU6IOrQ\r\n"
	"0nhxSBMplNAB1KR9vpEE3SPJqh5ei0iVIO04vY+9dFBFy73kf1QaFv70L3G08en7\r\n"
	"Vk8TV/zxOrDzXdVg+6VDTFB0xVkAsoVcOLwl+c4Q03kCAwEAAaOCARUwggERMF4G\r\n"
	"CCsGAQUFBwEBBFIwUDAnBggrBgEFBQcwAoYbaHR0cDovL3RleGEuY29tL3Jvb3Qt\r\n"
	"Y2EuY3J0MCUGCCsGAQUFBzABhhlodHRwOi8vb2NzcC50ZXhhLmNvbTo5MDgwMB8G\r\n"
	"A1UdIwQYMBaAFLtDdn8BTKWMB6V0hT4+5LRj6eafMBIGA1UdEwEB/wQIMAYBAf8C\r\n"
	"AQAwLAYDVR0fBCUwIzAhoB+gHYYbaHR0cDovL3RleGEuY29tL3Jvb3QtY2EuY3Js\r\n"
	"MB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAOBgNVHQ8BAf8EBAMCAQYw\r\n"
	"HQYDVR0OBBYEFOxbzpeN2GJAcXCJacb0MwvUBfDEMA0GCSqGSIb3DQEBCwUAA4IC\r\n"
	"AQBkv4Wk6oC4KEx/WS3W7r7vTOM/YWyMMW3UuSD2VhvFSjG0OY55/DJop+AFzxm7\r\n"
	"/5sHaraHcd9bG0V7TnRki4kbwfRIb0nhbIrUwy/wJ2flemQRny7Y1Ca2px0wYgur\r\n"
	"uGjf8Z7CsNuF0DvYIuB6KIm5UgbvjqJhT7j/ZMff5pqrLCF5fbmrx9VNCEsJ24WM\r\n"
	"PdQb80GXtTC4O19SREu7ZtrFS2XHdBsLKx73nOBcV56HBUUeDqGY+dgrnixo/8Zj\r\n"
	"qzoNMhjqzBGuw5OI00IsUERJc9h9mSwPH50VCwtHmPqfsPahGl++8TMYJZgwvDE3\r\n"
	"+2gIrR6FvEBKViXH3i94RKgP75yTRNGqcXeTlZs5PZlntgrF6IHWuvOS5aFMhEjy\r\n"
	"kGE3pfI64dswIOEPVgLRqwlrTSZxDF/aMDLjwJD6Llx2y3iw4UfjKETPwbhIOtf/\r\n"
	"7+rumQgptzj4+4uS/8FZ/4c0PwA2mDM8tr6/RXWolboHFNwFVrMJ+45CBDdeLA6d\r\n"
	"4kXwZNOqg4I/2lSfloB6jZfAzD38mGY0vgI/Rv6FqG6jZd+LYn5DdLUAPAU74Xyn\r\n"
	"7+55DR3VayxWISoFDwfU7eKFpq3qGQ8/9K9gY0DlI7Gl2BjCCeghj/ukCDu7jhMY\r\n"
	"yOmIadki8duSmqZAGmhRB01FWyE8maTlILIzxQtT7fiitA==\r\n"
	"-----END CERTIFICATE-----\r\n"

	// root CA
	"-----BEGIN CERTIFICATE-----\r\n"
	"MIIFNTCCAx2gAwIBAgIRAK3bnKXNe5ENrV3HeRgf3uMwDQYJKoZIhvcNAQELBQAw\r\n"
	"NDELMAkGA1UEBhMCSVQxEDAOBgNVBAoMB1RleGEgR0UxEzARBgNVBAMMClVmZmlj\r\n"
	"aW8gRlcwHhcNMTgwOTIxMDg0MDE3WhcNMzgwOTIxMDg0MDE3WjA0MQswCQYDVQQG\r\n"
	"EwJJVDEQMA4GA1UECgwHVGV4YSBHRTETMBEGA1UEAwwKVWZmaWNpbyBGVzCCAiIw\r\n"
	"DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANK5XWoH2FaI+W4aoMLLY+8jsan7\r\n"
	"KmVlhZDNiifgY1gB6wwXel3iZWxwSUwhM+hpgD5O3STw6mhG+LtPAZn/Vmtns/RB\r\n"
	"LKx/wiu880maOfW5CCCvIHqjH5mxknkuqTJ29iVFjMrzH1qhCiEQI07RJz1Ec/Xv\r\n"
	"0+z8Sahs0gHroE+qQZw4Bq8Grl/7QBOW8D13+kF62zPrXLv9vu7IiK8lYHa6Fxxk\r\n"
	"bHXOymsuqQI5MROaFJxPii8QAc5TdWAMhL+5CagDE7EdIVwMnOVWw47i1ZWVA/VP\r\n"
	"GSy4dmDqG6CDlgmvsWPa5Z0UD4BVFDEx+bzAHV1QFFgsyh4X7Y44hZ/SZPHRJHVn\r\n"
	"1M+Q9lWHKozIPjHgq9An0FhilGCYhX0DXp/kTknj3DYa2oUaTHEc/x3VdYBMYa0u\r\n"
	"WM9URErAh7nKdOiR5zao0XJ0tl1EPAALrTt5M28TroHERXlDUSviC6TUjzfnMTIb\r\n"
	"p1U+ZKXRmZyMJMGmRYbgfwuj544bfRMR3df+70nsi4KJfxxzj9x119xLEjlaVRMI\r\n"
	"q+BVIwRiJULDhXgSuSHwUsUrISiA7FO6Sbp8PoHgyO+OnhOQ4wJy1dm4hXUz/7is\r\n"
	"N9Nbj77zcKE9nJDa3GOGXGuSK09Gdba4PybHMz4QjLGzfQQ1d7bV5wk8aWulWePc\r\n"
	"D6rT+Y8ppRiORlUpAgMBAAGjQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/\r\n"
	"BAQDAgEGMB0GA1UdDgQWBBS7Q3Z/AUyljAeldIU+PuS0Y+nmnzANBgkqhkiG9w0B\r\n"
	"AQsFAAOCAgEALVYU06amDjMwjx9QNV+4GwQ5MIz64iHZnctNfdhjPnt3IUtlxs+g\r\n"
	"G8rwAFPEt9aLHoS32gwGxDrqXTNU9mZVms8ebND2x+D2jz8IlUR+x+/3D9IyDIt9\r\n"
	"2nxNKLSSnkFC39n+H0d/6tWCGPYo6NReszKwW46SQ4aP57XNyPsi0/OMHuCVOcG9\r\n"
	"uW/tBLh2n5ZIN9znYcXtnTyZN036WCMgP7jX7dt5YqWOsnepXZayEgBQ4XwUvTCG\r\n"
	"nom1EDmv+9A3qEIdwerDqdO9Qcohm5EwCDn5KubdMtG3M2Jlr1M3I46aBIBd3oLT\r\n"
	"lfMvY3TARaL1dWjkMo4sJRAUJWrpww3tOHUVK7oZ6177VogBJrNQ3cQS9oBKampx\r\n"
	"AUPuZ0AGRAJl2xlrvwKkaLQDWmOZxVqVH18PEATbq6R1yXzj6NoSl1Dz6gdbgWk+\r\n"
	"4uQJ3P76CTMQdz5uH7cD+ZEancdoDaHdjJ1afW5LjveBiP1ZO4+6oIS+fUW+qlvX\r\n"
	"VPx5DhXNYuqoBCCWlfyw60iN0oeFmCMnpnwHOeFDYE0ke2H9A+uHFSfC4txslwMT\r\n"
	"R/1CODlTGgSmsBGubKgpLspddkZ2oW4L73FWkVNdafHWoAdLCdbe3i5pLhnp4M+9\r\n"
	"t+SRUHm1N81a5XX9hEvbLe+jAhg2PDcNr4zlosOgxKUug1mzCn/S6U0=\r\n"
	"-----END CERTIFICATE-----\r\n"
} ;

static const char SRV_CERT[] = {
	"-----BEGIN CERTIFICATE-----\r\n"
	"MIIENjCCAx6gAwIBAgIRAK3bnKXNe5ENrV3HeRgf3uUwDQYJKoZIhvcNAQELBQAw\r\n"
	"WDELMAkGA1UEBhMCSVQxEDAOBgNVBAoMB1RleGEgR0UxIjAgBgNVBAMMGTIwOCAt\r\n"
	"IEFkYXR0YXRvcmUgRG9JUCBPQkQxEzARBgNVBAsMClVmZmljaW8gRlcwHhcNMTgw\r\n"
	"OTIxMDg0OTI3WhcNMzgwOTIxMDg0OTI3WjBEMQswCQYDVQQGEwJJVDEQMA4GA1UE\r\n"
	"CgwHVGV4YSBHRTETMBEGA1UECwwKVWZmaWNpbyBGVzEOMAwGA1UEAwwFU0M2MzUw\r\n"
	"ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDby/WciNrRHERdx/5GkiN3\r\n"
	"nxp+9h/LdTRO5OzQJS0TtrOvvDyfdFPi2aYDG+kDwHP4OndIP4TEEx9pOXJHhMNy\r\n"
	"63HSslQxHp0agPPGK3EBPbqamEAuYyjFNGMSJqCfqiGOq0lRbcSv8VHI6SH48T6U\r\n"
	"evISjPBeCxcrJHEbazcb/l2BvmUkUocvXEVnOwMBLSSepJnvo+XKtR4fMBCxhoz6\r\n"
	"VwUaGpqvEoUedHYHzWD3nCkUYYZXDnuL3FwFr4d+wUOaFZ02WnANvGV3dW9EijZp\r\n"
	"3guyqW7Vku4ttcWK4cz5oB9+CWGtkOIVDlV5ye2/087G5f/zJX47GnFfjFSShJKl\r\n"
	"AgMBAAGjggENMIIBCTBdBggrBgEFBQcBAQRRME8wJgYIKwYBBQUHMAKGGmh0dHA6\r\n"
	"Ly90ZXhhLmNvbS9zdWItY2EuY3J0MCUGCCsGAQUFBzABhhlodHRwOi8vb2NzcC50\r\n"
	"ZXhhLmNvbTo5MDgxMB8GA1UdIwQYMBaAFOxbzpeN2GJAcXCJacb0MwvUBfDEMAwG\r\n"
	"A1UdEwEB/wQCMAAwKwYDVR0fBCQwIjAgoB6gHIYaaHR0cDovL3RleGEuY29tL3N1\r\n"
	"Yi1jYS5jcmwwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMA4GA1UdDwEB\r\n"
	"/wQEAwIFoDAdBgNVHQ4EFgQUosYhkPr7mLxhVLSZfACDVpyWiWIwDQYJKoZIhvcN\r\n"
	"AQELBQADggEBALcOI5rnrGAVyJDxSorCNxxfw9WS6z4rZOzTViEebovVUMFVZUDr\r\n"
	"nDNapvScOM6haTtpqVy/S/Z3kedusM5SCw2tByBty3ancRpLsMeGhtpLvxrJOpJI\r\n"
	"M+FP0gkPxEOcalC5N5vO8n2cMY+0Z3DD0G5Q4nNVprqVWjxq+NcuX0TZiSYkZe2J\r\n"
	"4p5wOBY81hmdmstCsiR5v4L6IjJVRrkBIgcHfGsyb3m27K+Qs0LPpvi0eFQ7pVma\r\n"
	"xH8RZtf9fenw2U2nkhBEklRvie67W52MdQ8hZIMYe8HEtVjLIf6gXGDR5wKMjU7r\r\n"
	"yQNhd4xAwCSOl3T5I8uBV0MAVo/ckC/NlzA=\r\n"
	"-----END CERTIFICATE-----\r\n"
} ;

static const char SRV_KEY[] = {
	"-----BEGIN RSA PRIVATE KEY-----\r\n"
	"MIIEowIBAAKCAQEA28v1nIja0RxEXcf+RpIjd58afvYfy3U0TuTs0CUtE7azr7w8\r\n"
	"n3RT4tmmAxvpA8Bz+Dp3SD+ExBMfaTlyR4TDcutx0rJUMR6dGoDzxitxAT26mphA\r\n"
	"LmMoxTRjEiagn6ohjqtJUW3Er/FRyOkh+PE+lHryEozwXgsXKyRxG2s3G/5dgb5l\r\n"
	"JFKHL1xFZzsDAS0knqSZ76PlyrUeHzAQsYaM+lcFGhqarxKFHnR2B81g95wpFGGG\r\n"
	"Vw57i9xcBa+HfsFDmhWdNlpwDbxld3VvRIo2ad4Lsqlu1ZLuLbXFiuHM+aAffglh\r\n"
	"rZDiFQ5Vecntv9POxuX/8yV+OxpxX4xUkoSSpQIDAQABAoIBAAvfVIEEE23ALSEz\r\n"
	"sFR3iFrpyTCactU2m4C3dOM5Xtn1wHb5n/ys9+sE/qakV03Qk3MRFWhdpfpBXiz8\r\n"
	"4WNjlHscpKVQ5KNSmAHafVBzAEOk5fN7zduzl3wvfDp6w6pcMjvWnLs9RqaKTnSf\r\n"
	"wyoDPfIfQfwmiMVLrBC0gzeL7wof9Zr4raUSg4dHUjpoit6hMfomCcYMl6X/km75\r\n"
	"bUtmdOhm9x4mMLWZq7rFIfb1V8+75sL+yGqcZ1y3jNeviU+KNfwct3+zA9gQWN+E\r\n"
	"Icr6Je2/byMOHlmRM2DTfXJbSvZakNzyM/4hPIK9reDhrmPNFWQTIMyxmONIrLuC\r\n"
	"lgS/roECgYEA+obj1m99BLIjFN8EHLtOXOtAeR45orOlfBkOPiDvtwW/612ja8HZ\r\n"
	"Pw6+uf9TQFJBoDmhR6uv3pB5HtbegXBpqKo4EKcSJahipDkjGnENDdQklotmVbhq\r\n"
	"mJ0EmP6wxrs3PRnWrcuqRSTG6+WZpg7sEQmIQM84959zObW2wwsf3tkCgYEA4Jk0\r\n"
	"w4PvyhjuczozoAqQ7Hwj6rgT8Cw72/twe7mu0pEXkbNnWzMNyaUypOKiIpfHaD9N\r\n"
	"vPpHnljmKdt7Ciwr0NyUGo8ZwHucN9opvVC+wZ0llDbKqXrpfsiaKF1G6cbVIFRb\r\n"
	"Icd9ISJz6h3pLGSTxJkro/ZV/kzcJt9lzSpqiq0CgYAcc8NecCz/ooePcECUTsV4\r\n"
	"khMxbjhXfRWXQXU3ox/2ZkXEok7UByD4I2GP2CqJTI49dy4U6K/BlCDdWsPMaYrm\r\n"
	"Z+aUJZVPB4+kXQTalOpJnsVE/7HwnFAm4vZJtes3tr1wSAX0mQPOdH3O/rVzgZBX\r\n"
	"4wBBdAdhQA+jBzspbZMCCQKBgQCXuOdb7JTgAVeTn42gX4LnPjVFKnTNmhQV1xV1\r\n"
	"f0oKFNnHI1p+0U5PGbnMiQzeMYoTcjAhqTEYVxWk0Q+dH5m5zkh+aI0M6nPthwML\r\n"
	"ULCMOoxYQ2tEcjOp4fnBqsFsy1TOMi4d85Uj/RIw5WPPCWKJPK+uY4pT77gIyoEK\r\n"
	"x8yRQQKBgCi4QvprqOghsENAKzUMGRv5UMIdDa4hAjxz3VJ9Ag0TRPa3FMpVrDBJ\r\n"
	"0RtBzMb6A2luBP8fP67YGdPo4mVwYjL12OS4srM3ocEYL5KfgOFREX4Tku6slIc1\r\n"
	"gJgBqdDYBGTbvXwkF6FfUddGvjMJB03515gBCYBbAxFxgbvbsSwb\r\n"
	"-----END RSA PRIVATE KEY-----\r\n"
} ;


static esp_err_t event_handler(void *ctx, system_event_t *event)
{
	UNUSED(ctx) ;

	switch (event->event_id) {
    case SYSTEM_EVENT_WIFI_READY:               /**< ESP32 WiFi ready */
    	ESP_LOGI(TAG, "SYSTEM_EVENT_WIFI_READY");
    	break ;
    case SYSTEM_EVENT_SCAN_DONE:                /**< ESP32 finish scanning AP */
    	ESP_LOGI(TAG, "SYSTEM_EVENT_SCAN_DONE");
    	break ;
    case SYSTEM_EVENT_STA_START:                /**< ESP32 station start */
		ESP_LOGI(TAG, "SYSTEM_EVENT_STA_START");
		break;
    case SYSTEM_EVENT_STA_STOP:                 /**< ESP32 station stop */
    	ESP_LOGI(TAG, "SYSTEM_EVENT_STA_STOP");
    	break ;
    case SYSTEM_EVENT_STA_CONNECTED:            /**< ESP32 station connected to AP */
    	ESP_LOGI(TAG, "SYSTEM_EVENT_STA_CONNECTED");
    	break ;
    case SYSTEM_EVENT_STA_DISCONNECTED:         /**< ESP32 station disconnected from AP */
		ESP_LOGI(TAG, "SYSTEM_EVENT_STA_DISCONNECTED");
		break;
    case SYSTEM_EVENT_STA_AUTHMODE_CHANGE:      /**< the auth mode of AP connected by ESP32 station changed */
    	ESP_LOGI(TAG, "SYSTEM_EVENT_STA_AUTHMODE_CHANGE");
    	break ;
    case SYSTEM_EVENT_STA_GOT_IP:               /**< ESP32 station got IP from connected AP */
		ESP_LOGI(TAG, "SYSTEM_EVENT_STA_GOT_IP");
		break ;
    case SYSTEM_EVENT_STA_LOST_IP:              /**< ESP32 station lost IP and the IP is reset to 0 */
    	ESP_LOGI(TAG, "SYSTEM_EVENT_STA_LOST_IP");
    	break ;
    case SYSTEM_EVENT_STA_WPS_ER_SUCCESS:       /**< ESP32 station wps succeeds in enrollee mode */
    	ESP_LOGI(TAG, "SYSTEM_EVENT_STA_WPS_ER_SUCCESS");
    	break ;
    case SYSTEM_EVENT_STA_WPS_ER_FAILED:        /**< ESP32 station wps fails in enrollee mode */
    	ESP_LOGI(TAG, "SYSTEM_EVENT_STA_WPS_ER_FAILED");
    	break ;
    case SYSTEM_EVENT_STA_WPS_ER_TIMEOUT:       /**< ESP32 station wps timeout in enrollee mode */
    	ESP_LOGI(TAG, "SYSTEM_EVENT_STA_WPS_ER_TIMEOUT");
    	break ;
    case SYSTEM_EVENT_STA_WPS_ER_PIN:           /**< ESP32 station wps pin code in enrollee mode */
    	ESP_LOGI(TAG, "SYSTEM_EVENT_STA_WPS_ER_PIN");
    	break ;
    case SYSTEM_EVENT_AP_START:                 /**< ESP32 soft-AP start */
    	ESP_LOGI(TAG, "SYSTEM_EVENT_AP_START");
    	AP_evn(AP_EVN_START, &event->event_info) ;
    	break ;
    case SYSTEM_EVENT_AP_STOP:                  /**< ESP32 soft-AP stop */
    	ESP_LOGI(TAG, "SYSTEM_EVENT_AP_STOP");
    	AP_evn(AP_EVN_STOP, &event->event_info) ;
    	break ;
    case SYSTEM_EVENT_AP_STACONNECTED:          /**< a station connected to ESP32 soft-AP */
    	ESP_LOGI(TAG, "SYSTEM_EVENT_AP_STACONNECTED");
    	AP_evn(AP_EVN_STACONNECTED, &event->event_info) ;
    	break ;
    case SYSTEM_EVENT_AP_STADISCONNECTED:       /**< a station disconnected from ESP32 soft-AP */
    	ESP_LOGI(TAG, "SYSTEM_EVENT_AP_STADISCONNECTED");
    	AP_evn(AP_EVN_STADISCONNECTED, &event->event_info) ;
    	break ;
    case SYSTEM_EVENT_AP_STAIPASSIGNED:         /**< ESP32 soft-AP assign an IP to a connected station */
    	ESP_LOGI(TAG, "SYSTEM_EVENT_AP_STAIPASSIGNED");
    	AP_evn(AP_EVN_STAIPASSIGNED, &event->event_info) ;
    	break ;
    case SYSTEM_EVENT_AP_PROBEREQRECVED:        /**< Receive probe request packet in soft-AP interface */
    	ESP_LOGI(TAG, "SYSTEM_EVENT_AP_PROBEREQRECVED");
    	break ;
    case SYSTEM_EVENT_GOT_IP6:                  /**< ESP32 station or ap or ethernet interface v6IP addr is preferred */
    	ESP_LOGI(TAG, "SYSTEM_EVENT_GOT_IP6");
    	break ;
    case SYSTEM_EVENT_ETH_START:                /**< ESP32 ethernet start */
    	ESP_LOGI(TAG, "SYSTEM_EVENT_ETH_START");
    	break ;
    case SYSTEM_EVENT_ETH_STOP:                 /**< ESP32 ethernet stop */
    	ESP_LOGI(TAG, "SYSTEM_EVENT_ETH_STOP");
    	break ;
    case SYSTEM_EVENT_ETH_CONNECTED:            /**< ESP32 ethernet phy link up */
    	ESP_LOGI(TAG, "SYSTEM_EVENT_ETH_CONNECTED");
    	break ;
    case SYSTEM_EVENT_ETH_DISCONNECTED:         /**< ESP32 ethernet phy link down */
    	ESP_LOGI(TAG, "SYSTEM_EVENT_ETH_DISCONNECTED");
    	break ;
    case SYSTEM_EVENT_ETH_GOT_IP:               /**< ESP32 ethernet got IP from connected AP */
    	ESP_LOGI(TAG, "SYSTEM_EVENT_ETH_GOT_IP");
    	break ;

	default:
		ESP_LOGE(TAG, "? evento %d %p ?", event->event_id, &event->event_info) ;
		break;
	}

	return ESP_OK;
}

typedef struct {
    void * buffer;
    uint16_t len;
} tcpip_adapter_eth_input_t;

static xQueueHandle comes ;


// ========= ECO ==============================================================

static osPoolId mp = NULL ;

static void eco_conn(const char * ip)
{
	ESP_LOGI(TAG, "eco connesso a %s", ip) ;
}

static void eco_msg(TLS_SRV_MSG * pM)
{
	tcpip_adapter_eth_input_t msg = {
		.buffer = pM
	} ;

    if (xQueueSend(comes, &msg, 0) != pdTRUE) {
    	ESP_LOGE(TAG, "eco: msg non inviato!!!") ;
    }
}

static void eco_scon(void)
{
	ESP_LOGI(TAG, "eco disconnesso") ;
}

static TLS_SRV_CFG ecoCfg = {
	.porta = 7,

	.conn = eco_conn,
	.msg = eco_msg,
	.scon = eco_scon,

	.srv_cn = CLN_CN,

	.srv_cert = (const unsigned char *) SRV_CERT,
	.dim_srv_cert = sizeof(SRV_CERT),

	.cert_chain = (const unsigned char *) CERT_CHAIN,
	.dim_cert_chain = sizeof(CERT_CHAIN),

	.srv_key = (const unsigned char *) SRV_KEY,
	.dim_srv_key = sizeof(SRV_KEY),
	.pw_srv_key = NULL,
	.dim_pw_srv_key = 0
} ;

static TLS_SRV * ecoSrv = NULL ;

static void inizia_eco(void)
{
	if (NULL == mp) {
		osPoolDef(mp, 100, TLS_SRV_MSG) ;
		mp = osPoolCreate(osPool(mp)) ;
		assert(mp) ;
		ecoCfg.mp = mp ;
	}
	if (NULL == ecoSrv)
		ecoSrv = TLS_SRV_beg(&ecoCfg) ;
}

void app_main()
{
	esp_log_level_set("*", ESP_LOG_INFO) ;

	// questa la fanno sempre
	esp_err_t ret = nvs_flash_init();
	if (ret == ESP_ERR_NVS_NO_FREE_PAGES) {
		ESP_ERROR_CHECK( nvs_flash_erase() );
		ESP_ERROR_CHECK( nvs_flash_init() );
	}

	// Varie
    gpio_install_isr_service(0) ;

    tcpip_adapter_init();

    ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL));

    // ap
    S_AP sap = {
    		.ssid = "TLS",
    		.max_connection = 1,
    		.auth = AUTH_OPEN
    } ;
    CHECK_IT( AP_beg(&sap) ) ;

#ifdef NDEBUG
    ESP_LOGI(TAG, "vers %d", VER) ;
#else
    ESP_LOGI(TAG, "vers %d (dbg)", VER) ;
#endif
    ESP_LOGI(TAG, "data %s", DATA) ;

    comes = xQueueCreate(100, sizeof(tcpip_adapter_eth_input_t)) ;

    inizia_eco() ;

    tcpip_adapter_eth_input_t msg;
	while (true) {
    	if (xQueueReceive(comes, &msg, (portTickType) portMAX_DELAY) == pdTRUE) {
    		TLS_SRV_MSG * pM = msg.buffer ;

    		if (!TLS_SRV_tx(ecoSrv, pM->mem, pM->dim))
    			ESP_LOGE(TAG, "ERR eco TX[%d]", pM->dim) ;

   			osPoolFree(mp, pM) ;
    	}
	}
}
