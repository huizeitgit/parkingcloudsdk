#ifndef _PARKCLOUDSESSION_H_
#define _PARKCLOUDSESSION_H_

#if (defined(WIN32)) || (defined(_WIN32))
#ifdef PKLIB_EXPORTS
#define PKLIBAPI  __declspec(dllexport)
#else
#define PKLIBAPI  __declspec(dllimport)
#endif 
#else
#define PKLIBAPI  __attribute__ ((visibility("default")))
#endif

#ifdef __cplusplus
extern "C"
{
#endif
	
	typedef struct sParkCloudSession *parkCloudSession;

	/*
	@description: call back function when receive parking cloud message
	@param s: parkCloudSession instance
	@param cloudTopic: message topic of cloud server
	@param tid: transaction id of message
	@param message: message string pointer
	@param userdata: user data pointer passed by create session
	*/
	typedef void(*callbackOnCloudMessage)(parkCloudSession s, const char *cloudTopic, int tid, const char *message, void *userdata);

	typedef enum _e_parkcloudsession_mqtt_status
	{
		E_ST_MQTTCONN = 0, //MQTT Connected
		E_ST_MQTTDISCONN   //MQTT Disconnected
	} e_parkcloudsession_mqtt_status;

	typedef enum _e_parkcloudsession_attach_status
	{
		E_ST_CLOUDATTACHED = 0, //Cloud Server Attached
		E_ST_CLOUDDETACHED      //Cloud Server Dettached
	} e_parkcloudsession_attach_status;

	typedef enum _e_parkcloudsession_errno
	{
		E_SUCC = 0,            //Success
		E_UNKNOWN,             //Unknown Error
		E_SYSBUSY,             //System Busy
		E_REACHSESMAX,         //Reach Max Session Number
		E_PARAILEGAL,          //Paramter Ilegal
		E_PRIVKEYLOADFAIL,     //Load Device Private Key File Failed
		E_PUBKEYLOADFAIL,      //Load Cloud Public Key File Failed
		E_OUTOFMEM,            //Out of Memory
		E_CLOUDDETACHED,       //Detached from Cloud Server
		E_TOPICINVALID,        //MQTT Topic Invalid
		E_MSGLENINVALID,       //Message Length Invalid
		E_MSGCTXINVALID,       //Message Format Invalid
		E_GETJSONOBJFAIL,      //Get JSON Object Failed
		E_GENJSONSTRFAIL,      //Get JSON String Failed
		E_AESENCRYPTFAIL,      //AES Encrypt Failed
		E_HEXENCRYPTFAIL       //HEX Encode Failed
	} e_parkcloudsession_errno;

	typedef struct
	{
		const char *vendor;          //Device Vendor
		const char *sn;              //Device SN
		const char *version;         //Device Version
		const char *devprivkeyfile;  //Device Private Key File Path
		const char *cloudpubkeyfile; //Cloud Public Key File Path
		const char *mqttaddr;        //MQTT Server IP Address
		unsigned int mqttport; //MQTT Server Port
		const char *mqttuser;        //MQTT Username
		const char *mqttpwd;         //MQTT User Password
		int  libinfoprint;     //Print Lib Info to Console(0-noprint other-print)
		int  liberrprint;      //Print Lib Error to Console(0-noprint other-print)
	} s_parkcloudsession_para, *ps_parkcloudsession_para;

	PKLIBAPI e_parkcloudsession_errno createSession(parkCloudSession *pps, const ps_parkcloudsession_para ppara, callbackOnCloudMessage cb, void *userdata);

	PKLIBAPI void releaseSession(parkCloudSession s);
	
	PKLIBAPI e_parkcloudsession_mqtt_status getMQTTStatus(parkCloudSession s);
	PKLIBAPI e_parkcloudsession_attach_status getAttachStatus(parkCloudSession s);
		
	PKLIBAPI e_parkcloudsession_errno sendCloudMessage(parkCloudSession s, const char *cloudTopic, int tid, const char *message);

#ifdef __cplusplus
}
#endif

#endif