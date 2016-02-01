#ifndef _RULE_HANDLE_H_
#define _RULE_HANDLE_H_

#include <dirent.h>
#include <sys/types.h>

#include <framework.h>
#include "msg_areasms_task_def.h"
#include "QueryMsgDef.h"
//#include "seg_stats_thread.h"
#include "aes_handle.h"

#define MAX_FIELDS_NUMS					16
#define MAX_AES_RESULT_CHAR_NUMS		256

const U8 fieldpoint[10] = {0,};

enum _enum_GatherTypes
{
	TimeSegment = 1,//时间段
	TimeDot			//时间点
};

enum _enum_ResultTypes{
	StatsAllNum = 1,//不分本地和外地
	Record,			//详细
	StatsUnfoldNum	//本地外地分别展示
};


//任务种类 1:详细记录时间点 2:详细记录时间段 3:指定基站时间点统计 4:指定基站时间段统计 5:指定号码到指定的基站下面产生文件  6: 7:
enum _enum_TaskTypes{
	Record_TimeDot = 1,
	Record_TimeSegment,
	Stats_TimeDot,
	Stats_TimeSegment,
	PhoneTouch
};

enum _enum_CoreQueryTypes{
	QueryMDN_Status = 1,
	QueryCC_Phone,
	QueryMDNs_Status,//phone touch query
	QueryIMSI_Status 
};

enum _enum_EncryptTypes{
	AES_Encrypt = 0x01,
	Replace_Encrypt = 0x02,
	Fetch_Field = 0x04,
	Filter_Field = 0x08
};

enum _enum_Grade{
	Grade_Area = 1,
	Grade_BasicStation,
	Grade_Section,
	Grade_All
};


enum _enum_fields{
	FL_MDN = 1,
	FL_IMSI,
	FL_CC,
	FL_PowerState,
	FL_BusyState,
	FL_PosFlag,
	FL_CurTime,
	FL_EventID,
	FL_LAT,
	FL_LON
};


typedef map<string,pair<U64/*local*/,U64/*nation*/> > CCStatsResultMap;
typedef CCStatsResultMap::iterator MapCCiterator;

typedef struct _StruQueryObjects
{												
	U32					ObjectsFlag;//第一位:基站CC 第二位:MDN 第三位:IMSI    0:有参数  1:无参数
	CCStatsResultMap 	MapCC;
	vector<U64>			VectorMDN_IMSI;
}StruQueryObjects;

typedef struct _UserDefineRule
{
	U8	_param[];	//buffer of parameter
}UserDefineRule;


typedef char Arrary_AesResult[256];

typedef struct _StruEncryptAES : public UserDefineRule
{												
	U8			FieldID[MAX_FIELDS_NUMS];//需要AES加密的字段ID
	U8			IsAes[MAX_FIELDS_NUMS];//标记加密字段
	U8			ResPlace[MAX_FIELDS_NUMS];//定位结果在数组array的位置          
	U8 			TotalNums;//需要AES加密的字段总数
}StruEncryptAES;

typedef char Arrary_RepResult[32];
typedef struct _StruEncryptReplace : public UserDefineRule
{											
	U8			FieldID[MAX_FIELDS_NUMS];//需要AES加密的字段ID
	U8			StartAddr[MAX_FIELDS_NUMS];//替换起始位置
	U8			EndAddr[MAX_FIELDS_NUMS];//替换结束位置
	U8			To[MAX_FIELDS_NUMS];//需要替换的字符
	U8			IsRep[MAX_FIELDS_NUMS];//标记加密字段
	U8			ResPlace[MAX_FIELDS_NUMS];//定位结果在数组array的位置          
	U8			TotalNums;//需要替换加密的字段总数
}StruEncryptReplace;

typedef struct _StruFetch : public UserDefineRule
{											
	U8			FieldID[MAX_FIELDS_NUMS];//需要索取的字段ID
	U8			TotalNums;//需要索取的字段总数
}StruFetch;

typedef struct _StruFilter : public UserDefineRule
{		
	U8			FieldID[MAX_FIELDS_NUMS];//需要过滤的字段ID
	U64			FilterVaule[MAX_FIELDS_NUMS];//过滤匹配值
	U8			TotalNums;//需要过滤的字段总数
}StruFilter;




#endif//_RULE_HANDLE_H_

