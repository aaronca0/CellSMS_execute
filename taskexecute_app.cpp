#include "taskexecute_app.h"
#include "msg_receiver.h"
#include "Rule_Handle_Packages.h"
#include "workthread.h"

CMsgReceiver g_MsgReceiverThread;

map<U64,CWorkThread*> g_TaskWorkThreadMap;
set<CWorkThread*> g_RecycleSet;
CThreadLock g_WorkThreadMapLock;

U32 g_CheckInterval;
char g_DestIP[32];

CTaskExecute::CTaskExecute()
{
	;
}
CTaskExecute::~CTaskExecute()
{	
	;
}

void CTaskExecute::GetCfgSubscribeInfo(
				CCfgPathPairList &paths, CCfgDynamicSubscriberList &dynamic_nodes)
{
	CApplication::GetCfgSubscribeInfo(paths,dynamic_nodes);
}


BOOL CTaskExecute::Initialize()
{
	LoadRemoteAgents();

	CXMLElement* pEleCheckTime = GetConfig().GetElement( (string(CFG_APP_ELEM_NAME) + "/checkstatustime_sec").c_str());
	if( pEleCheckTime )
	{
		g_CheckInterval = atoi(pEleCheckTime->GetText());
		TRACE_LOG("get config g_CheckInterval:%u",g_CheckInterval);
	}else
	{
		g_CheckInterval = 120;
		TRACE_LOG("g_CheckInterval use default values:120");
	}

	CXMLElement* pEleDestIp = GetConfig().GetElement( (string(CFG_APP_ELEM_NAME) + "/dest_ip").c_str());
	if( pEleDestIp )
	{
		memset(g_DestIP,0,32);
		strcpy(g_DestIP,pEleDestIp->GetText());
		TRACE_LOG("get config g_DestIP:%s",g_DestIP);
	}else
	{
		TRACE_LOG("[error]_: g_DestIP Not configure !");
		return FALSE;
	}
	
	CRemoteMsgAgent* pToDispatchAgent = GetRemoteAgent(AGENT_NAME_TASK_DISPATCH);
	//CRemoteMsgAgent* pToOiddAgent = GetRemoteAgent(AGENT_NAME_QUERY_OIDD);

	if(NULL != pToDispatchAgent)
	{
		pToDispatchAgent->SetTarget(&g_MsgReceiverThread);
		g_MsgReceiverThread.Start();
	}

	
	if( !pToDispatchAgent->Start())
	{
		TRACE_LOG("the pToDispatchAgent start is failure !");
		return FALSE;
	}
	/**/
	
	TRACE_LOG("Initialize is success !");
	return TRUE;
}

typedef struct _strutest
{
	int MDN;
	U32 IMSI;
	U64	CC;
}strutest;

const char FieldChar[10][16] = {"MDN","IMSI","CC","PowerState","BusyState","PosFlag","CurTime","EventID","LAT","LON"};

#define GETFIELD(res,stru,value) 	\
	res=stru.value;

						

BOOL CTaskExecute::Running()
{
//	U32 wTest = 10;
//	string strTest = "10";
//	CreateClassOject(CTaskExecute,strTest)
/*	
	string str_test;
	string str_result;
	char ctest[20] = "460036181956181";
	str_test.assign("123456");
	str_result.clear();
	str_result.assign(encrypt(string(ctest),1));
	TRACE_LOG("the Encrypt result:%s",str_result.c_str());
	str_test.assign(decrypt(str_result,1));
	TRACE_LOG("the Decrypt result:%s",str_test.c_str());
	
	strutest stru_test;
	stru_test.MDN = 1;
	stru_test.IMSI = 2;
	stru_test.CC = 3;
	U64 uResult;

	char buffer[2048];
	char str_cc[1024]="M;15385858593;18918195337;_M;C;C0194,1;C0198,1;C0468,1;C0488,1;C0517,1;C0517,2;C1003,3;C1044,1;C1169,2;C1259,1;C1288,1;C1288,2;C1312,2;C1373,1;C1591,1;C1594,1;C1793,2;C1987,1;C1987,2;C1987,3;C4636,1;C4636,2;C4636,3;_C";
	char str_mdn[1024]="M;15385858593;18918195337;_M";
	TaskPackageMsg* pWebTaskMsg = (TaskPackageMsg*)buffer;
	memset(pWebTaskMsg,0,sizeof(TaskPackageMsg));
	pWebTaskMsg->type = MSG_TYPE_TASK_ADD_DEL;
	pWebTaskMsg->len = sizeof(TaskPackageMsg) - sizeof(TRawMsg) + strlen(str_cc) + 1;
	strcpy(pWebTaskMsg->OperateObjects,str_cc);
	pWebTaskMsg->ExeFlag = 1;
	pWebTaskMsg->PackageOverFlag = 1;
	pWebTaskMsg->InvokeID = 99999991233;
	pWebTaskMsg->Workstarttime = 0;
	pWebTaskMsg->Workstoptime = 24*3600;
	pWebTaskMsg->Taskendtime = 1453151140;
	pWebTaskMsg->Isphone = 		1;	//	0:非号码触发 1:号码触发
	pWebTaskMsg->Gathertype = 	2;	//	1:时间段 2:时间点
	pWebTaskMsg->Resulttype = 	3;	//	1:统计全部号码 2:详情 3:统计省内号码	
	pWebTaskMsg->Grade = 		3;	//	1:区 2:基站 3:扇区 4:全部
	pWebTaskMsg->Filefrequence = 2;
	strcpy(pWebTaskMsg->Filedirectory,"/project/caohui/result_store");

	OSSleep(2000);//(U32 nMS)
	g_MsgReceiverThread.SendMsg(pWebTaskMsg);
	
	*/	
	//while(1);
	return TRUE;
}

BOOL CTaskExecute::Terminate()
{
	return TRUE;
}


CTaskExecute* GetCTaskExecuteApp()
{
	return (CTaskExecute*)GetApplication();
}


IMPLEMENT_APPLICATION(CTaskExecute,"taskexecute")
	




