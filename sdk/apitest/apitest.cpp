// apitest.cpp : 定义控制台应用程序的入口点。
//

#if defined(_WIN32) || defined(WIN32)
#include <windows.h>
#define mssleep(ms) Sleep(ms)
#else
#include <unistd.h>
#define mssleep(ms) sleep((ms)/1000)
#endif

#include <stdio.h>
#include <stdlib.h>
#include "parkcloudsession.h"

void onMessage(parkCloudSession s, const char *cloudTopic, int tid, const char *message, void *userdata)
{
	printf("app receive message with cloudTopic:%s tid:%d message:%s\n\n", cloudTopic, tid , message);
	
	//send message response here

	//do something else here
}

int main(int argc, char* argv[])
{
	e_parkcloudsession_errno eno;
	parkCloudSession s;
	s_parkcloudsession_para p;
	p.vendor = "jshz";
	p.sn = "9840bb1f5ca5";
	p.version = "1.0";
	p.devprivkeyfile = "../key/mcu_priv_key.pem";
	p.cloudpubkeyfile = "../key/cloud_pub_key.pem";
	p.mqttaddr = "116.62.81.201";
	p.mqttport = 1883;
	p.mqttuser = "eparkingpartner";
	p.mqttpwd = "jiangsu_huizeit_d6b47f42";
	p.liberrprint = 1;
	p.libinfoprint = 0;

	eno = createSession(&s, &p, onMessage, NULL);
	if (eno == E_SUCC)
	{
		char msg[256];
		int tid = 1000;
		int count = 0;
		while (1)
		{
			if (count % 5 == 0)
			{
				sprintf(msg, "{\"msg\":\"groundsensor\",\"uid\":\"testuid%d\",\"time\":\"2017-05-10 00:00:00\"}", tid);
				sendCloudMessage(s, "/service/groundsensor/v1", tid++, msg);
			}
			
			if (count > 30)
			{
				releaseSession(s);
				break;
			}

			count++;
			mssleep(1000);
		}
	}
	else
	{
		printf("createSession failed with errno:%d\n", eno);
	}

	printf("Press any key to exit.\n");
	getchar();
	return 0;
}

