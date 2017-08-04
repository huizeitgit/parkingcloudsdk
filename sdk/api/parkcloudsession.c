#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include <mosquitto.h>

#include <pthread.h>

#include "cJSON.h"
#include "parkcloudsession.h"

#define MAX_TOPICPRE_LEN    (16)
#define MAX_VENDOR_LEN      (32)
#define MAX_SN_LEN          (32)
#define MAX_VER_LEN         (32)
#define MAX_TOPIC_LEN       (MAX_TOPICPRE_LEN + MAX_VENDOR_LEN + MAX_SN_LEN)
#define MAX_MQTTADDR_LEN    (64)
#define MAX_MQTTUSER_LEN    (32)
#define MAX_MQTTPWD_LEN     (32)

#define MSG_HEAD_ATTACHCHAR ('a')
#define MSG_HEAD_DATACHAR   ('d')
#define MSG_HEAD_ATTACH     ("1a")
#define MSG_HEAD_DATA       ("1d")
#define MSG_HEAD_LEN        (2)
#define MSG_TOKEN_LEN       (64)
#define MSG_SIGNKEYCRC_LEN  (32)
#define MSG_SIGNKEYTMS_LEN  (32)
#define MSG_SIGNKEY_LEN     (MSG_SIGNKEYCRC_LEN+MSG_SIGNKEYTMS_LEN)
#define MAX_MSG_LEN         (16384)
#define MAX_PAYLOAD_LEN     (MAX_MSG_LEN-384)
#define MAX_ATTACH_TIMEOUT  (3)
#define MAX_RECV_TIMEOUT    (60)

#define CLOUD_ATTACH_TOPIC  ("/service/attach/v1")

typedef enum
{
	PUBLICKEY = 0,
	PRIVATEKEY = 1
} RSAKeyType;

struct sParkCloudSession
{
	char vendor[MAX_VENDOR_LEN];
	char sn[MAX_SN_LEN];
	char ver[MAX_VER_LEN];
	char topic[MAX_TOPIC_LEN];
	char mqttaddr[MAX_MQTTADDR_LEN];
	unsigned int mqttport;
	char mqttuser[MAX_MQTTUSER_LEN];
	char mqttpwd[MAX_MQTTPWD_LEN];
	RSA* devPrivKey;
	RSA* cloudPubKey;
	struct mosquitto *mosq;
	callbackOnCloudMessage cb;
	void *ud;

	int  libinfoprint;
	int  liberrprint;

	int mqttconnected;
	int cloudattached;
	char token[MSG_TOKEN_LEN];
	char signkey[MSG_SIGNKEY_LEN];
	int mqttlooprun;
	pthread_t mqttloopthread;

	uint32_t lastattachtime;
	uint32_t lastrecvtime;
};

//initial flag
static int mosquittoInit = 0;

//one process can has one sesson only 
static parkCloudSession glbSession = NULL;
static pthread_mutex_t  glbSessionMutex = PTHREAD_MUTEX_INITIALIZER;

//Attach Message Buffers
static int attachTid = 0;
static char _attachMsg[MAX_MSG_LEN];
static char _frameBuffer[MAX_PAYLOAD_LEN];
static char _frameExtraBuffer[MAX_PAYLOAD_LEN];

//Data Message Buffers
static char _dataMsg[MAX_MSG_LEN];
static char _dataBuffer[MAX_PAYLOAD_LEN];
static char _dataExtraBuffer[MAX_PAYLOAD_LEN];
static char _dataCrcBuffer[MSG_SIGNKEYCRC_LEN];
static char _dataTimeBuffer[MSG_SIGNKEYTMS_LEN];

static const char*logPrefix = "******";

void logError(int logflag, const char *format, ...)
{
	va_list args;
	if (!logflag)
		return;
	
	char *xformat = malloc(strlen(logPrefix) + strlen(format) + 1);
	if (xformat)
	{
		strcpy(xformat, logPrefix);
		strcat(xformat, format);

		va_start(args, format);
		vfprintf(stderr, xformat, args);
		va_end(args);

		free(xformat);
	}
}

void logInfo(int logflag, const char *format, ...)
{
	va_list args;
	if (!logflag)
		return;
	
	char *xformat = malloc(strlen(logPrefix) + strlen(format) + 1);
	if (xformat)
	{
		strcpy(xformat, logPrefix);
		strcat(xformat, format);

		va_start(args, format);
		vfprintf(stdout, xformat, args);
		va_end(args);

		free(xformat);
	}
}

uint32_t toNetOrder(uint32_t x)
{
	static int orderInit = 0;
	static int isLittle = 0;
	if (!orderInit)
	{
		short t = 0x0102;
		if (*(unsigned char*)&t == 0x01)
		{
			isLittle = 0;
		}
		else
		{
			isLittle = 1;
		}
		orderInit = 1;
	}

	if (isLittle)
	{
		uint32_t y;
		unsigned char *s = (unsigned char *)&x;
		unsigned char *d = (unsigned char *)&y;
		d[0] = s[3];
		d[1] = s[2];
		d[2] = s[1];
		d[3] = s[0];
		return y;
	}
	else
		return x;
}

static const uint32_t crc32tab[] = {
	0x00000000L, 0x77073096L, 0xee0e612cL, 0x990951baL,
	0x076dc419L, 0x706af48fL, 0xe963a535L, 0x9e6495a3L,
	0x0edb8832L, 0x79dcb8a4L, 0xe0d5e91eL, 0x97d2d988L,
	0x09b64c2bL, 0x7eb17cbdL, 0xe7b82d07L, 0x90bf1d91L,
	0x1db71064L, 0x6ab020f2L, 0xf3b97148L, 0x84be41deL,
	0x1adad47dL, 0x6ddde4ebL, 0xf4d4b551L, 0x83d385c7L,
	0x136c9856L, 0x646ba8c0L, 0xfd62f97aL, 0x8a65c9ecL,
	0x14015c4fL, 0x63066cd9L, 0xfa0f3d63L, 0x8d080df5L,
	0x3b6e20c8L, 0x4c69105eL, 0xd56041e4L, 0xa2677172L,
	0x3c03e4d1L, 0x4b04d447L, 0xd20d85fdL, 0xa50ab56bL,
	0x35b5a8faL, 0x42b2986cL, 0xdbbbc9d6L, 0xacbcf940L,
	0x32d86ce3L, 0x45df5c75L, 0xdcd60dcfL, 0xabd13d59L,
	0x26d930acL, 0x51de003aL, 0xc8d75180L, 0xbfd06116L,
	0x21b4f4b5L, 0x56b3c423L, 0xcfba9599L, 0xb8bda50fL,
	0x2802b89eL, 0x5f058808L, 0xc60cd9b2L, 0xb10be924L,
	0x2f6f7c87L, 0x58684c11L, 0xc1611dabL, 0xb6662d3dL,
	0x76dc4190L, 0x01db7106L, 0x98d220bcL, 0xefd5102aL,
	0x71b18589L, 0x06b6b51fL, 0x9fbfe4a5L, 0xe8b8d433L,
	0x7807c9a2L, 0x0f00f934L, 0x9609a88eL, 0xe10e9818L,
	0x7f6a0dbbL, 0x086d3d2dL, 0x91646c97L, 0xe6635c01L,
	0x6b6b51f4L, 0x1c6c6162L, 0x856530d8L, 0xf262004eL,
	0x6c0695edL, 0x1b01a57bL, 0x8208f4c1L, 0xf50fc457L,
	0x65b0d9c6L, 0x12b7e950L, 0x8bbeb8eaL, 0xfcb9887cL,
	0x62dd1ddfL, 0x15da2d49L, 0x8cd37cf3L, 0xfbd44c65L,
	0x4db26158L, 0x3ab551ceL, 0xa3bc0074L, 0xd4bb30e2L,
	0x4adfa541L, 0x3dd895d7L, 0xa4d1c46dL, 0xd3d6f4fbL,
	0x4369e96aL, 0x346ed9fcL, 0xad678846L, 0xda60b8d0L,
	0x44042d73L, 0x33031de5L, 0xaa0a4c5fL, 0xdd0d7cc9L,
	0x5005713cL, 0x270241aaL, 0xbe0b1010L, 0xc90c2086L,
	0x5768b525L, 0x206f85b3L, 0xb966d409L, 0xce61e49fL,
	0x5edef90eL, 0x29d9c998L, 0xb0d09822L, 0xc7d7a8b4L,
	0x59b33d17L, 0x2eb40d81L, 0xb7bd5c3bL, 0xc0ba6cadL,
	0xedb88320L, 0x9abfb3b6L, 0x03b6e20cL, 0x74b1d29aL,
	0xead54739L, 0x9dd277afL, 0x04db2615L, 0x73dc1683L,
	0xe3630b12L, 0x94643b84L, 0x0d6d6a3eL, 0x7a6a5aa8L,
	0xe40ecf0bL, 0x9309ff9dL, 0x0a00ae27L, 0x7d079eb1L,
	0xf00f9344L, 0x8708a3d2L, 0x1e01f268L, 0x6906c2feL,
	0xf762575dL, 0x806567cbL, 0x196c3671L, 0x6e6b06e7L,
	0xfed41b76L, 0x89d32be0L, 0x10da7a5aL, 0x67dd4accL,
	0xf9b9df6fL, 0x8ebeeff9L, 0x17b7be43L, 0x60b08ed5L,
	0xd6d6a3e8L, 0xa1d1937eL, 0x38d8c2c4L, 0x4fdff252L,
	0xd1bb67f1L, 0xa6bc5767L, 0x3fb506ddL, 0x48b2364bL,
	0xd80d2bdaL, 0xaf0a1b4cL, 0x36034af6L, 0x41047a60L,
	0xdf60efc3L, 0xa867df55L, 0x316e8eefL, 0x4669be79L,
	0xcb61b38cL, 0xbc66831aL, 0x256fd2a0L, 0x5268e236L,
	0xcc0c7795L, 0xbb0b4703L, 0x220216b9L, 0x5505262fL,
	0xc5ba3bbeL, 0xb2bd0b28L, 0x2bb45a92L, 0x5cb36a04L,
	0xc2d7ffa7L, 0xb5d0cf31L, 0x2cd99e8bL, 0x5bdeae1dL,
	0x9b64c2b0L, 0xec63f226L, 0x756aa39cL, 0x026d930aL,
	0x9c0906a9L, 0xeb0e363fL, 0x72076785L, 0x05005713L,
	0x95bf4a82L, 0xe2b87a14L, 0x7bb12baeL, 0x0cb61b38L,
	0x92d28e9bL, 0xe5d5be0dL, 0x7cdcefb7L, 0x0bdbdf21L,
	0x86d3d2d4L, 0xf1d4e242L, 0x68ddb3f8L, 0x1fda836eL,
	0x81be16cdL, 0xf6b9265bL, 0x6fb077e1L, 0x18b74777L,
	0x88085ae6L, 0xff0f6a70L, 0x66063bcaL, 0x11010b5cL,
	0x8f659effL, 0xf862ae69L, 0x616bffd3L, 0x166ccf45L,
	0xa00ae278L, 0xd70dd2eeL, 0x4e048354L, 0x3903b3c2L,
	0xa7672661L, 0xd06016f7L, 0x4969474dL, 0x3e6e77dbL,
	0xaed16a4aL, 0xd9d65adcL, 0x40df0b66L, 0x37d83bf0L,
	0xa9bcae53L, 0xdebb9ec5L, 0x47b2cf7fL, 0x30b5ffe9L,
	0xbdbdf21cL, 0xcabac28aL, 0x53b39330L, 0x24b4a3a6L,
	0xbad03605L, 0xcdd70693L, 0x54de5729L, 0x23d967bfL,
	0xb3667a2eL, 0xc4614ab8L, 0x5d681b02L, 0x2a6f2b94L,
	0xb40bbe37L, 0xc30c8ea1L, 0x5a05df1bL, 0x2d02ef8dL
};

uint32_t caclCRC32(const unsigned char *buf, uint32_t size)
{
	uint32_t i, crc;
	crc = 0xFFFFFFFF;
	for (i = 0; i < size; i++)
		crc = crc32tab[(crc ^ buf[i]) & 0xff] ^ (crc >> 8);
	return crc ^ 0xFFFFFFFF;
}

uint32_t epochSeconds()
{
	time_t t = time(NULL);
	return (uint32_t)t;
}

RSA*   LoadRSAKey(const char* keyFileName, RSAKeyType keyType)
{
	RSA *pRSAKey = NULL;
	BIO *key = NULL;
	key = BIO_new(BIO_s_file());
	if (BIO_read_filename(key, keyFileName) > 0)
	{
		if (keyType == PUBLICKEY)
		{
			pRSAKey = PEM_read_bio_RSA_PUBKEY(key, NULL, NULL, NULL);
		}
		else if (keyType == PRIVATEKEY)
		{
			pRSAKey = PEM_read_bio_RSAPrivateKey(key, NULL, NULL, NULL);
		}
	}

	BIO_free_all(key);
	return pRSAKey;
}

void   UnLoadRSAKey(RSA* pRSAKey)
{
	if (pRSAKey != NULL)
		RSA_free(pRSAKey);
}

int EncodeRSAKeyFile(RSA* pRSAPubKey, const char* strData, char *outbuf, unsigned int outbufsize)
{
	if (pRSAPubKey == NULL || strData == NULL || outbuf == NULL)
	{
		return -1;
	}

	unsigned int nLen = RSA_size(pRSAPubKey);
	if (outbufsize <= nLen)
		return -2;

	int dataLen = strlen(strData);
	char* pEncode = malloc(nLen + 1);
	int ret = RSA_public_encrypt(dataLen, (const unsigned char*)strData, (unsigned char*)pEncode, pRSAPubKey, RSA_PKCS1_OAEP_PADDING);
	if (ret >= 0)
	{
		memcpy(outbuf, pEncode, ret);
	}
	free(pEncode);
	return ret;
}


int DecodeRSAKeyFile(RSA* pRSAPrivKey, const char* strData, int dataLen, char *outbuf, unsigned int outbufsize)
{
	if (pRSAPrivKey == NULL || strData == NULL || dataLen <= 0 || outbuf == NULL)
	{
		return -1;
	}

	unsigned int nLen = RSA_size(pRSAPrivKey);
	if (outbufsize <= nLen)
		return -2;

	int ret = RSA_private_decrypt(dataLen, (const unsigned char*)strData, (unsigned char*)outbuf, pRSAPrivKey, RSA_PKCS1_OAEP_PADDING);

	return ret;
}

int aesEncrypt(const char* key, const char* data, char* output)
{
	AES_KEY aes_key;
	if (AES_set_encrypt_key((const unsigned char*)key, strlen(key) * 8, &aes_key) < 0)
	{
		return -1;
	}

	int dataLen = strlen(data);
	int padNum = 0;
	if (dataLen % AES_BLOCK_SIZE  > 0) {
		padNum = AES_BLOCK_SIZE - dataLen%AES_BLOCK_SIZE;
	}
	dataLen += padNum;
	char* encryptData = (char*)malloc(dataLen);
	if (encryptData == NULL)
	{
		return -2;
	}

	memcpy(encryptData, data, strlen(data));
	char* p = (encryptData + strlen(data));
	while (padNum > 0) {
		*(p++) = '\0';
		padNum--;
	}

	unsigned char iv[AES_BLOCK_SIZE];
	memset(iv, '0', AES_BLOCK_SIZE);
	AES_cbc_encrypt((const unsigned char*)(encryptData), (unsigned char*)output, dataLen, &aes_key, iv, AES_ENCRYPT);
	free(encryptData);
	return dataLen;
}

int aesDecrypt(const char* key, const char* in, int len, char* out)
{
	unsigned char iv[AES_BLOCK_SIZE];
	memset(iv, '0', AES_BLOCK_SIZE);

	AES_KEY aes_key;
	if (AES_set_decrypt_key((unsigned char*)key, 128, &aes_key) < 0)
		return -1;

	AES_cbc_encrypt((unsigned char*)in, (unsigned char*)out, len, &aes_key, iv, AES_DECRYPT);
	return len;
}

int HexDecode(const char *s, int slen, unsigned char *buf, int bufSize)
{
	static unsigned char HexChar2ByteTable[256];
	static int HexChar2ByteTableInit = 0;
	if (!HexChar2ByteTableInit)
	{
		HexChar2ByteTableInit = 1;
		memset(&HexChar2ByteTable, 0, sizeof(HexChar2ByteTable));
		HexChar2ByteTable['0'] = 0;
		HexChar2ByteTable['1'] = 1;
		HexChar2ByteTable['2'] = 2;
		HexChar2ByteTable['3'] = 3;
		HexChar2ByteTable['4'] = 4;
		HexChar2ByteTable['5'] = 5;
		HexChar2ByteTable['6'] = 6;
		HexChar2ByteTable['7'] = 7;
		HexChar2ByteTable['8'] = 8;
		HexChar2ByteTable['9'] = 9;
		HexChar2ByteTable['A'] = 10;
		HexChar2ByteTable['B'] = 11;
		HexChar2ByteTable['C'] = 12;
		HexChar2ByteTable['D'] = 13;
		HexChar2ByteTable['E'] = 14;
		HexChar2ByteTable['F'] = 15;
		HexChar2ByteTable['a'] = 10;
		HexChar2ByteTable['b'] = 11;
		HexChar2ByteTable['c'] = 12;
		HexChar2ByteTable['d'] = 13;
		HexChar2ByteTable['e'] = 14;
		HexChar2ByteTable['f'] = 15;
	}

	if (slen % 2 != 0 || bufSize < (slen / 2))
		return 0;

	int bufIdx = 0;
	for (int idx = 0; idx < slen; idx += 2)
	{
		buf[bufIdx] = (HexChar2ByteTable[(unsigned char)s[idx]] << 4) | (HexChar2ByteTable[(unsigned char)s[idx + 1]]);
		bufIdx++;
	}
	return bufIdx;
}

int HexEncode(const char *s, int slen, char *buf, int buflen)
{
	static char Byte2HexCharTable[16];
	static int Byte2HexCharTableInit = 0;
	if (!Byte2HexCharTableInit)
	{
		Byte2HexCharTableInit = 1;
		Byte2HexCharTable[0] = '0';
		Byte2HexCharTable[1] = '1';
		Byte2HexCharTable[2] = '2';
		Byte2HexCharTable[3] = '3';
		Byte2HexCharTable[4] = '4';
		Byte2HexCharTable[5] = '5';
		Byte2HexCharTable[6] = '6';
		Byte2HexCharTable[7] = '7';
		Byte2HexCharTable[8] = '8';
		Byte2HexCharTable[9] = '9';
		Byte2HexCharTable[10] = 'a';
		Byte2HexCharTable[11] = 'b';
		Byte2HexCharTable[12] = 'c';
		Byte2HexCharTable[13] = 'd';
		Byte2HexCharTable[14] = 'e';
		Byte2HexCharTable[15] = 'f';
	}

	if (buflen < (slen * 2))
		return 0;

	int bufIdx = 0;
	for (int i = 0; i < slen; i++)
	{
		buf[bufIdx++] = Byte2HexCharTable[(unsigned char)s[i] >> 4];
		buf[bufIdx++] = Byte2HexCharTable[(unsigned char)s[i] & 0xf];
	}
	return bufIdx;
}

void sendAttachMessage(parkCloudSession s, const char *k2)
{
	char *out;
	cJSON *payload, *data;
	data = cJSON_CreateObject();
	if (!data)
	{
		logError(s->liberrprint, "%s(%d) cJSON_CreateObject failed\n", __FILE__, __LINE__);
		return;
	}

	if (k2 == NULL)
	{
		cJSON_AddStringToObject(data, "vendor", s->vendor);
		cJSON_AddStringToObject(data, "sn", s->sn);
		cJSON_AddStringToObject(data, "version", s->ver);
	}
	else
	{
		cJSON_AddStringToObject(data, "k2", k2);
	}

	payload = cJSON_CreateObject();
	if (!payload)
	{
		cJSON_Delete(data);
		logError(s->liberrprint, "%s(%d) cJSON_CreateObject failed\n", __FILE__, __LINE__);
		return;
	}

	cJSON_AddStringToObject(payload, "src", s->topic);
	cJSON_AddStringToObject(payload, "dst", CLOUD_ATTACH_TOPIC);
	cJSON_AddNumberToObject(payload, "tid", attachTid++);
	cJSON_AddItemToObject(payload, "data", data);

	out = cJSON_Print(payload);
	if (!out)
	{
		cJSON_Delete(payload);
		logError(s->liberrprint, "%s(%d) cJSON_Print failed\n", __FILE__, __LINE__);
		return;
	}

	strcpy(_attachMsg, MSG_HEAD_ATTACH);
	strcat(_attachMsg, out);
	mosquitto_publish(s->mosq, NULL, CLOUD_ATTACH_TOPIC, strlen(_attachMsg), _attachMsg, 2, true);
	logInfo(s->libinfoprint, "sendAttachMessage success with:%s\n", _attachMsg);

	cJSON_Delete(payload);
	free(out);
}

void *loopMQTT(void *param)
{
	parkCloudSession ps = (parkCloudSession)param;

	logInfo(ps->libinfoprint, "start mosquitto_loop\n");
		
	while ( ps->mqttlooprun ){
		mosquitto_loop(ps->mosq, 1000, 1);
		uint32_t now = epochSeconds();
		
			if (!ps->cloudattached)
			{
				if ((now - ps->lastattachtime) >= MAX_ATTACH_TIMEOUT)
				{
					ps->lastattachtime = now;
					logInfo(ps->libinfoprint, "mosquitto_loop retry attach cloud for detached\n");
					sendAttachMessage(ps, NULL);
				}
			}
			else
			{
				if ((now - ps->lastrecvtime) > MAX_RECV_TIMEOUT)
				{
					if ((now - ps->lastattachtime) >= MAX_ATTACH_TIMEOUT)
					{
						ps->lastattachtime = now;
						logInfo(ps->libinfoprint, "mosquitto_loop retry attach cloud for receive timeout\n");
						sendAttachMessage(ps, NULL);
					}
				}
			}
	}
	logInfo(ps->libinfoprint, "exit mosquitto_loop\n");
	return NULL;
}

void startLoopMQTT(parkCloudSession ps)
{
	ps->mqttlooprun = 1;

	pthread_t pid;
	pthread_create(&pid, NULL, loopMQTT, ps);
	ps->mqttloopthread = pid;
}

void stopLoopMQTT(parkCloudSession ps)
{
	ps->mqttlooprun = 0;
	pthread_join(ps->mqttloopthread, NULL);
}

void onMQTTConnect(struct mosquitto *mosq, void *userdata, int reason) {
	parkCloudSession ps = (parkCloudSession)userdata;
	logError(ps->liberrprint, "onMQTTConnect with MQTT broker(%s:%u) for reason:%d\n", ps->mqttaddr, ps->mqttport, reason);

	ps->mqttconnected = 1;
	ps->cloudattached = 0;

	mosquitto_subscribe(ps->mosq, NULL, ps->topic, 0);
}

void onMQTTDisconnect(struct mosquitto *mosq, void *userdata, int reason) {
	parkCloudSession ps = (parkCloudSession)userdata;
	logError(ps->liberrprint, "onMQTTDisconnect with MQTT broker(%s:%u) for reason:%d\n", ps->mqttaddr, ps->mqttport, reason);

	ps->mqttconnected = 0;
	ps->cloudattached = 0;
	
	if (ps->mqttlooprun)
	{
		logInfo(ps->libinfoprint, "reconnect to MQTT broker(%s:%u)\n", ps->mqttaddr, ps->mqttport);
		mosquitto_reconnect(ps->mosq);
	}
}

void onMQTTMessage(struct mosquitto *mosq, void *userdata, const struct mosquitto_message *message) {
	const char *payload = message->payload;
	int payloadlen = message->payloadlen;
	const char *cloudtopic = message->topic;
	parkCloudSession ps = (parkCloudSession)userdata;

	if (ps == NULL || ps != glbSession)
	{
		logError(ps->liberrprint, "onMQTTMessage can not get parkCloudSession\n");
		return;
	}

	if (payloadlen <= MSG_HEAD_LEN)
	{
		logError(ps->liberrprint, "onMQTTMessage get message with illegal length:%d\n", payloadlen);
		return;
	}

	ps->lastrecvtime = epochSeconds();
	logInfo(ps->libinfoprint, "onMQTTMessage get message with timestamp:%u topic:%s length:%d payload:%s\n", ps->lastrecvtime, cloudtopic, payloadlen, payload);

	if (payload[1] != MSG_HEAD_ATTACHCHAR && payload[1] != MSG_HEAD_DATACHAR)
	{
		logError(ps->liberrprint, "onMQTTMessage get message with wrong head\n");
		return;
	}

	if (payload[1] == MSG_HEAD_ATTACHCHAR)
	{
		cJSON *objPayload = cJSON_Parse(payload + MSG_HEAD_LEN);
		if (objPayload == NULL)
		{
			logError(ps->liberrprint, "onMQTTMessage cJSON_Parse failed\n");
			return;
		}

		cJSON * objData = cJSON_GetObjectItem(objPayload, "data");
		if (objData == NULL)
		{
			cJSON_Delete(objPayload);
			logError(ps->liberrprint, "onMQTTMessage cJSON_GetObjectItem data failed\n");
			return;
		}

		cJSON * objK1 = cJSON_GetObjectItem(objData, "k1");
		if (objK1)
		{
			char *k1 = objK1->valuestring;

			int decodeLen = HexDecode(k1, strlen(k1), (unsigned char *)_frameBuffer, sizeof(_frameBuffer));
			if (decodeLen == 0)
			{
				cJSON_Delete(objPayload);
				logError(ps->liberrprint, "onMQTTMessage HexDecode k1(%s) failed\n", k1);
				return;
			}
			_frameBuffer[decodeLen] = '\0';

			int k1PlainLen = DecodeRSAKeyFile(ps->devPrivKey, (const char *)_frameBuffer, decodeLen, _frameExtraBuffer, sizeof(_frameExtraBuffer));
			if (k1PlainLen <= 0)
			{
				cJSON_Delete(objPayload);
				logError(ps->liberrprint, "onMQTTMessage RSADecode k1(%s) failed\n", k1);
				return;
			}
			_frameExtraBuffer[k1PlainLen] = '\0';

			//gen k2 
			int k2RsaLen = EncodeRSAKeyFile(ps->cloudPubKey, _frameExtraBuffer, _frameBuffer, sizeof(_frameBuffer));
			if (k2RsaLen == 0)
			{
				cJSON_Delete(objPayload);
				logError(ps->liberrprint, "onMQTTMessage RSAEncode k2 failed\n");
				return;
			}
			_frameBuffer[k2RsaLen] = '\0';
			
			int k2HexLen = HexEncode(_frameBuffer, k2RsaLen, _frameExtraBuffer, sizeof(_frameExtraBuffer));
			if (k2HexLen == 0)
			{
				cJSON_Delete(objPayload);
				logError(ps->liberrprint, "onMQTTMessage HexEncode k2 failed\n");
				return;
			}
			_frameExtraBuffer[k2HexLen] = '\0';

			//send k2
			cJSON_Delete(objPayload);
			sendAttachMessage(ps, _frameExtraBuffer);
		}
		else
		{
			cJSON * objRespCode = cJSON_GetObjectItem(objData, "respcode");
			if (objRespCode == NULL)
			{
				cJSON_Delete(objPayload);
				logError(ps->liberrprint, "onMQTTMessage cJSON_GetObjectItem respcode failed\n");
				return;
			}

			int respCode = objRespCode->valueint;
			if (respCode != 200)
			{
				cJSON_Delete(objPayload);
				logError(ps->liberrprint, "onMQTTMessage get k3 failed respcode:%d\n", respCode);
				return;
			}

			cJSON * objK3 = cJSON_GetObjectItem(objData, "k3");
			if (objK3 == NULL)
			{
				cJSON_Delete(objPayload);
				logError(ps->liberrprint, "onMQTTMessage cJSON_GetObjectItem k3 failed\n");
				return;
			}

			char *k3 = objK3->valuestring;

			int decodeLen = HexDecode(k3, strlen(k3), (unsigned char *)_frameBuffer, sizeof(_frameBuffer));
			if (decodeLen == 0)
			{
				cJSON_Delete(objPayload);
				logError(ps->liberrprint, "onMQTTMessage HexDecode k3(%s) failed\n", k3);
				return;
			}
			_frameBuffer[decodeLen] = '\0';

			int k3PlainLen = DecodeRSAKeyFile(ps->devPrivKey, (const char *)_frameBuffer, decodeLen, _frameExtraBuffer, sizeof(_frameExtraBuffer));
			if (k3PlainLen <= 0)
			{
				cJSON_Delete(objPayload);
				logError(ps->liberrprint, "onMQTTMessage RSADecode k3(%s) failed\n", k3);
				return;
			}
			_frameExtraBuffer[k3PlainLen] = '\0';

			cJSON *objJsonK3 = cJSON_Parse(_frameExtraBuffer);
			if (objJsonK3 == NULL)
			{
				cJSON_Delete(objPayload);
				logError(ps->liberrprint, "onMQTTMessage cJSON_Parse k3(%s) failed\n", _frameExtraBuffer);
				return;
			}

			cJSON *objToken = cJSON_GetObjectItem(objJsonK3, "token");
			cJSON *objSignKey = cJSON_GetObjectItem(objJsonK3, "signkey");
			if (objToken && objSignKey)
			{
				ps->cloudattached = 1;
				ps->lastattachtime = 0;
				strcpy(ps->token, objToken->valuestring);
				strcpy(ps->signkey, objSignKey->valuestring);
				logInfo(ps->libinfoprint, "onMQTTMessage cJSON_Parse k3 success with token:%s signkey:%s\n", ps->token, ps->signkey);
			}

			cJSON_Delete(objJsonK3);
			cJSON_Delete(objPayload);
			return;
		}
	}
	else if (payload[1] == MSG_HEAD_DATACHAR)
	{
		int headlen = 2;
		int tokenlen = 16;
		int signaturelen = 32;
		int contentlen = payloadlen - headlen - tokenlen - signaturelen;

		const char *token = payload + headlen;
		const char *content = payload + headlen + tokenlen;
		
		if (!ps->cloudattached)
		{
			logInfo(ps->libinfoprint, "onMQTTMessage receive data message before attached to cloud\n");
			return;
		}

		if (strncmp(ps->token, token, tokenlen) != 0)
		{
			logError(ps->liberrprint, "onMQTTMessage receive data message with token mismatch\n");
			return;
		}

		int decodeLen = HexDecode(content, contentlen, (unsigned char *)_frameBuffer, sizeof(_frameBuffer));
		if (decodeLen == 0)
		{
			logError(ps->liberrprint, "onMQTTMessage HexDecode data message failed\n");
			return;
		}
		_frameBuffer[decodeLen] = '\0';
		
		int contentPlainLen = aesDecrypt(ps->signkey, (char *)_frameBuffer, decodeLen, (char *)_frameExtraBuffer);
		if (contentPlainLen == 0)
		{
			logError(ps->liberrprint, "onMQTTMessage RSADecode data message failed\n");
			return;
		}
		_frameExtraBuffer[contentPlainLen] = '\0';
		
		cJSON *objPayload = cJSON_Parse(_frameExtraBuffer);
		if (objPayload == NULL)
		{
			logError(ps->liberrprint, "onMQTTMessage cJSON_Parse data message failed\n");
			return;
		}

		cJSON * objSrc = cJSON_GetObjectItem(objPayload, "src");
		cJSON * objTid = cJSON_GetObjectItem(objPayload, "tid");
		cJSON * objData = cJSON_GetObjectItem(objPayload, "data");
		if (objSrc == NULL || objTid == NULL || objData == NULL)
		{
			cJSON_Delete(objPayload);
			logError(ps->liberrprint, "onMQTTMessage cJSON_GetObjectItem src/tid/data failed\n");
			return;
		}

		char strTopic[MAX_TOPIC_LEN];
		strcpy(strTopic, objSrc->valuestring);

		int iTid = objTid->valueint;

		char *strData = cJSON_PrintUnformatted(objData);

		cJSON_Delete(objPayload);

		if (strData)
		{
			if (ps->cb)
			{
				ps->cb(ps, strTopic, iTid, strData, ps->ud);
			}
			free(strData);
		}
	}
}

e_parkcloudsession_errno internalCreateSession(parkCloudSession *pps,
	const char *vendor, const char *sn, const char *version,
	const char *privkeyfile, const char *pubkeyfile,
	const char *mqttaddr, unsigned int mqttport, const char *mqttuser, const char *mqttpwd,
	callbackOnCloudMessage cb, void *userdata, 
	int  libinfoprint, int  liberrprint)
{
	RSA *priv = NULL;
	RSA *pub = NULL;
	parkCloudSession ps = NULL;
	*pps = NULL;

	if (pps == NULL || vendor == NULL || sn == NULL || version == NULL || privkeyfile == NULL || pubkeyfile == NULL
		|| mqttaddr == NULL || mqttuser == NULL || mqttpwd == NULL || cb == NULL)
		return E_PARAILEGAL;

	int vendorlen = strlen(vendor);
	int snlen = strlen(sn);
	int verlen = strlen(version);
	int mqttaddrlen = strlen(mqttaddr);
	int mqttuserlen = strlen(mqttuser);
	int mqttpwdlen = strlen(mqttpwd);

	if (vendorlen == 0 || (vendorlen + 1) > MAX_VENDOR_LEN ||
		snlen == 0 || (snlen + 1) > MAX_SN_LEN ||
		verlen == 0 || (verlen + 1) > MAX_VER_LEN ||
		mqttaddrlen == 0 || (mqttaddrlen + 1) > MAX_MQTTADDR_LEN ||
		mqttuserlen == 0 || (mqttuserlen + 1) > MAX_MQTTUSER_LEN ||
		mqttpwdlen == 0 || (mqttpwdlen + 1) > MAX_MQTTPWD_LEN
		)
		return E_PARAILEGAL;

	if (glbSession != NULL)
	{
		return E_REACHSESMAX;
	}

	if (!mosquittoInit)
	{
		mosquitto_lib_init();
		mosquittoInit = 1;
	}
	
	priv = LoadRSAKey(privkeyfile, PRIVATEKEY);
	if (priv == NULL)
		return E_PRIVKEYLOADFAIL;

	pub = LoadRSAKey(pubkeyfile, PUBLICKEY);
	if (pub == NULL)
	{
		UnLoadRSAKey(priv);
		return E_PUBKEYLOADFAIL;
	}

	ps = (parkCloudSession)malloc(sizeof(struct sParkCloudSession));
	if (ps == NULL)
	{
		UnLoadRSAKey(priv);
		UnLoadRSAKey(pub);
		return E_OUTOFMEM;
	}

	strcpy(ps->vendor, vendor);
	strcpy(ps->sn, sn);
	strcpy(ps->ver, version);
	strcpy(ps->topic, "/device/");
	strcat(ps->topic, vendor);
	strcat(ps->topic, "/");
	strcat(ps->topic, sn);

	strcpy(ps->mqttaddr, mqttaddr);
	ps->mqttport = mqttport;
	strcpy(ps->mqttuser, mqttuser);
	strcpy(ps->mqttpwd, mqttpwd);
	ps->cloudPubKey = pub;
	ps->devPrivKey = priv;
	ps->cb = cb;
	ps->ud = userdata;

	ps->libinfoprint = libinfoprint;
	ps->liberrprint = liberrprint;

	ps->mqttconnected = 0;
	ps->cloudattached = 0;
	ps->mqttlooprun = 0;
	ps->lastattachtime = 0;
	ps->lastrecvtime = 0;
	
	char clientid[MAX_VENDOR_LEN + MAX_SN_LEN];
	strcpy(clientid, vendor);
	strcat(clientid, sn);

	ps->mosq = mosquitto_new(clientid, false, ps);
	mosquitto_username_pw_set(ps->mosq, ps->mqttuser, ps->mqttpwd);
	mosquitto_connect_callback_set(ps->mosq, onMQTTConnect);
	mosquitto_disconnect_callback_set(ps->mosq, onMQTTDisconnect);
	mosquitto_message_callback_set(ps->mosq, onMQTTMessage);
	mosquitto_connect_async(ps->mosq, ps->mqttaddr, ps->mqttport, 5);
	logInfo(ps->libinfoprint, "createSession success\n");
	
	startLoopMQTT(ps);
	
	glbSession = ps;
	*pps = ps;
	return E_SUCC;
}

e_parkcloudsession_errno createSession(parkCloudSession *pps, const ps_parkcloudsession_para ppara,	callbackOnCloudMessage cb, void *userdata)
{
	e_parkcloudsession_errno eno;

	int iLock = pthread_mutex_trylock(&glbSessionMutex);
	if (iLock != 0)
		return E_SYSBUSY;
		
	eno = internalCreateSession(pps, ppara->vendor, ppara->sn, ppara->version, ppara->devprivkeyfile, ppara->cloudpubkeyfile,
		ppara->mqttaddr, ppara->mqttport, ppara->mqttuser, ppara->mqttpwd, cb, userdata,
		ppara->libinfoprint, ppara->liberrprint);
	pthread_mutex_unlock(&glbSessionMutex);

	return eno;
}

void internalReleaseSession(parkCloudSession s)
{
	if (s == NULL || s != glbSession)
	{
		return;
	}

	//exit loop thread
	stopLoopMQTT(s);
	if (s->mqttconnected)
		mosquitto_disconnect(s->mosq);
	
	mosquitto_destroy(s->mosq);

	UnLoadRSAKey(s->cloudPubKey);
	UnLoadRSAKey(s->devPrivKey);
	
	free(s);
	glbSession = NULL;
	
	CRYPTO_cleanup_all_ex_data();
}

void activeReconnMQTT(parkCloudSession s)
{
	if (s && s->mosq)
	{
		logInfo(s->libinfoprint, "%s\n", "activeReconnMQTT");
		mosquitto_reconnect(s->mosq);
	}
		
}

void releaseSession(parkCloudSession s)
{
	pthread_mutex_lock(&glbSessionMutex);

	internalReleaseSession(s);

	pthread_mutex_unlock(&glbSessionMutex);
}

e_parkcloudsession_mqtt_status getMQTTStatus(parkCloudSession s)
{
	if (s == NULL || s != glbSession)
	{
		return E_ST_MQTTDISCONN;
	}

	if (s->mqttconnected)
		return E_ST_MQTTCONN;
	else
		return E_ST_MQTTDISCONN;
}

e_parkcloudsession_attach_status getAttachStatus(parkCloudSession s)
{
	if (s == NULL || s != glbSession)
	{
		return E_ST_CLOUDDETACHED;
	}

	if (s->cloudattached)
		return E_ST_CLOUDATTACHED;
	else
		return E_ST_CLOUDDETACHED;
}

e_parkcloudsession_errno internalSendCloudMessage(parkCloudSession s, const char *cloudTopic, int tid, const char *message)
{
	cJSON *objData = NULL;

	if (s == NULL || s != glbSession)
	{
		return E_CLOUDDETACHED;
	}

	if (!s->mqttconnected || !s->cloudattached )
		return E_CLOUDDETACHED;

	if ( cloudTopic == NULL || strlen(cloudTopic) == 0)
		return E_TOPICINVALID;

	int msgLen = strlen(message);
	if ( message == NULL || msgLen == 0 || msgLen > MAX_PAYLOAD_LEN)
		return E_MSGLENINVALID;

	objData = cJSON_Parse(message);
	if (objData == NULL)
	{
		return E_MSGCTXINVALID;
	}

	cJSON *objPayload = cJSON_CreateObject();
	if (!objPayload)
	{
		cJSON_Delete(objData);
		return E_GETJSONOBJFAIL;
	}

	cJSON_AddStringToObject(objPayload, "src", s->topic);
	cJSON_AddStringToObject(objPayload, "dst", cloudTopic);
	cJSON_AddNumberToObject(objPayload, "tid", tid);
	cJSON_AddItemToObject(objPayload, "data", objData);

	char *strPayload = cJSON_PrintUnformatted(objPayload);
	if (!strPayload)
	{
		cJSON_Delete(objPayload);
		return E_GENJSONSTRFAIL;
	}

	strcpy(_dataMsg, MSG_HEAD_DATA);
	strcat(_dataMsg, s->token);
	
	int aeslen = aesEncrypt(s->signkey, strPayload, (char *)_dataBuffer);
	if (aeslen <= 0 || (size_t)(aeslen * 2)>sizeof(_dataBuffer))
	{
		cJSON_Delete(objPayload);
		free(strPayload);
		return E_AESENCRYPTFAIL;
	}
	_dataBuffer[aeslen] = '\0';

	int hexLen = HexEncode(_dataBuffer, aeslen, _dataExtraBuffer, sizeof(_dataExtraBuffer));
	if (hexLen == 0 || hexLen>sizeof(_dataExtraBuffer))
	{
		cJSON_Delete(objPayload);
		free(strPayload);
		return E_HEXENCRYPTFAIL;
	}
	_dataExtraBuffer[hexLen] = '\0';

	strcat(_dataMsg, _dataExtraBuffer);
		
	//sign
	uint32_t crc32 = toNetOrder(caclCRC32((const unsigned char *)_dataMsg, strlen(_dataMsg)));
	int hexCrc32Len = HexEncode( (const char *)&crc32, sizeof(crc32), _dataCrcBuffer, sizeof(_dataCrcBuffer));
	_dataCrcBuffer[hexCrc32Len] = '\0';

	uint32_t now = toNetOrder(epochSeconds());
	int hexTimeLen = HexEncode( (const char *)&now, sizeof(now), _dataTimeBuffer, sizeof(_dataTimeBuffer));
	_dataTimeBuffer[hexTimeLen] = '\0';

	strcpy(_dataBuffer, _dataCrcBuffer);
	strcat(_dataBuffer, _dataTimeBuffer);
	aeslen = aesEncrypt(s->signkey, _dataBuffer, (char *)_dataExtraBuffer);
	if (aeslen <= 0 || (size_t)(aeslen * 2)>sizeof(_dataExtraBuffer))
	{
		cJSON_Delete(objPayload);
		free(strPayload);
		return E_AESENCRYPTFAIL;
	}
	_dataExtraBuffer[aeslen] = '\0';

	hexLen = HexEncode(_dataExtraBuffer, aeslen, _dataBuffer, sizeof(_dataBuffer));
	_dataBuffer[hexLen] = '\0';
	
	strcat(_dataMsg, _dataBuffer);
	
	mosquitto_publish(s->mosq, NULL, cloudTopic, strlen(_dataMsg), _dataMsg, 2, true);
	logInfo(s->libinfoprint, "sendCloudMessage with cloudTopic:%s message:%s\n", cloudTopic, _dataMsg);
	
	cJSON_Delete(objPayload);
	free(strPayload);
	return E_SUCC;
}

e_parkcloudsession_errno sendCloudMessage(parkCloudSession s, const char *cloudTopic, int tid, const char *message)
{
	e_parkcloudsession_errno eno;

	int iLock = pthread_mutex_trylock(&glbSessionMutex);
	if (iLock != 0)
		return E_SYSBUSY;

	eno = internalSendCloudMessage(s, cloudTopic, tid, message);
	
	pthread_mutex_unlock(&glbSessionMutex);

	return eno;
}