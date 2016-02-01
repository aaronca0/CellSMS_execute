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
	TimeSegment = 1,//ʱ���
	TimeDot			//ʱ���
};

enum _enum_ResultTypes{
	StatsAllNum = 1,//���ֱ��غ����
	Record,			//��ϸ
	StatsUnfoldNum	//������طֱ�չʾ
};


//�������� 1:��ϸ��¼ʱ��� 2:��ϸ��¼ʱ��� 3:ָ����վʱ���ͳ�� 4:ָ����վʱ���ͳ�� 5:ָ�����뵽ָ���Ļ�վ��������ļ�  6: 7:
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
	U32					ObjectsFlag;//��һλ:��վCC �ڶ�λ:MDN ����λ:IMSI    0:�в���  1:�޲���
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
	U8			FieldID[MAX_FIELDS_NUMS];//��ҪAES���ܵ��ֶ�ID
	U8			IsAes[MAX_FIELDS_NUMS];//��Ǽ����ֶ�
	U8			ResPlace[MAX_FIELDS_NUMS];//��λ���������array��λ��          
	U8 			TotalNums;//��ҪAES���ܵ��ֶ�����
}StruEncryptAES;

typedef char Arrary_RepResult[32];
typedef struct _StruEncryptReplace : public UserDefineRule
{											
	U8			FieldID[MAX_FIELDS_NUMS];//��ҪAES���ܵ��ֶ�ID
	U8			StartAddr[MAX_FIELDS_NUMS];//�滻��ʼλ��
	U8			EndAddr[MAX_FIELDS_NUMS];//�滻����λ��
	U8			To[MAX_FIELDS_NUMS];//��Ҫ�滻���ַ�
	U8			IsRep[MAX_FIELDS_NUMS];//��Ǽ����ֶ�
	U8			ResPlace[MAX_FIELDS_NUMS];//��λ���������array��λ��          
	U8			TotalNums;//��Ҫ�滻���ܵ��ֶ�����
}StruEncryptReplace;

typedef struct _StruFetch : public UserDefineRule
{											
	U8			FieldID[MAX_FIELDS_NUMS];//��Ҫ��ȡ���ֶ�ID
	U8			TotalNums;//��Ҫ��ȡ���ֶ�����
}StruFetch;

typedef struct _StruFilter : public UserDefineRule
{		
	U8			FieldID[MAX_FIELDS_NUMS];//��Ҫ���˵��ֶ�ID
	U64			FilterVaule[MAX_FIELDS_NUMS];//����ƥ��ֵ
	U8			TotalNums;//��Ҫ���˵��ֶ�����
}StruFilter;




#endif//_RULE_HANDLE_H_

