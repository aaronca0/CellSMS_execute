#include "workthread.h"
#include "taskexecute_app.h"
#include <stdio.h>
#include <stdlib.h>


extern U32 g_CheckInterval;

extern char g_DestIP[32];

//const char FieldChar[10][16] = {"MDN","IMSI","CC","PowerState","BusyState","PosFlag","CurTime","EventID","LAT","LON"};

//#define GetField(stru,value) stru.$$value 


CWorkThread::CWorkThread()
{
	pRemoteAgent = NULL;
	iHeartValue = 0;
	iTaskType = 0;
	iCoreQueryType = 0;
	RuleID = 0;
	pRemoteMsgThreadTCPClient = NULL;
	m_CoreReturn_pf = NULL;
	memset(&StruAesRule,0,sizeof(StruEncryptAES));
	memset(&StruReplaceRule,0,sizeof(StruEncryptReplace));
	memset(&StruFetchRule,0,sizeof(StruFetch));
	memset(&StruFilterRule,0,sizeof(StruFilter));
	StruHandleObjects.MapCC.clear();
	StruHandleObjects.VectorMDN_IMSI.clear();
	StruHandleObjects.ObjectsFlag = 0;
	struTaskPackages.HandleObjects.clear();
	memset(&struTaskPackages,0,sizeof(TaskExecutePackages)-sizeof(string));
	bCloseFlag = 0;
}

CWorkThread::~CWorkThread()
{
	TRACE_LOG("~CWorkThread()");
}

BOOL CWorkThread::Prepare(long *pnResult)
{	
	long result = 0;
	strings strAddrParts;
	string strLocalAgentName;
	strLocalAgentName.assign(AGENT_NAME_OIDD_CORE); 
	divide_string(g_DestIP, strAddrParts, ":", TRUE);
	U32 nAddr = ip_string_to_addr(strAddrParts[0].c_str());
	U16 nPort = atoi(strAddrParts[1].c_str());
	pRemoteMsgThreadTCPClient = new CRemoteMsgThreadTCPClient(
			(strLocalAgentName.length()>0?strLocalAgentName.c_str():NULL), NULL,nPort, nAddr);
	if( NULL != pRemoteMsgThreadTCPClient)
	{
		pRemoteMsgThreadTCPClient->SetTarget(this);
	}
	if( (NULL == pRemoteMsgThreadTCPClient) || (!pRemoteMsgThreadTCPClient->Start()))
	{
		TRACE_LOG("[_Error]: the remote Agent create failure !");
		Cleanup(&result);
		return FALSE;
	}
	TRACE_LOG("[_Inform]: workthread agent connect remote_addr=%u, remote_port=%u is start",nAddr,nPort);
	OSSleep(1000);
	//set heart check timer
	INIT_MSG_HEADER(&TRawMsgTimer);
	TRawMsgTimer.type = MSG_HEART_BEAT_TIMER;
	m_CheckTimer.SetMessage(&TRawMsgTimer);
	m_CheckTimer.SetTime(g_CheckInterval*1000,TRUE);
	AddTimer(&m_CheckTimer);
	//initilize
	TRawMsgTimer.type = MSG_EXECUTE_TASK_INIT;
	CMsgThread::SendMsg(&TRawMsgTimer);
	
	return TRUE;
}


BOOL CWorkThread::CheckTime()
{	
	I32 iDaySec;
	
	TUGetTime(CurTime);
	iDaySec = CurTime.hour*3600 + CurTime.minute*60 + CurTime.second;
	
	if(struTaskPackages.Workstarttime > struTaskPackages.Workstoptime)
	{
		if( (struTaskPackages.Workstarttime < iDaySec) || ( iDaySec < struTaskPackages.Workstoptime))
			return TRUE;
		else
			return FALSE;
	}else
	{
		if( (struTaskPackages.Workstarttime < iDaySec) && ( iDaySec < struTaskPackages.Workstoptime))
			return TRUE;
		else
			return FALSE;
	}
}

BOOL CWorkThread::IsLive()
{
	if(1 == iHeartValue)
	{
		iHeartValue = 0;
		return TRUE;
	}
	else
	{
		iHeartValue = 0;
		return FALSE;
	}	
}

BOOL CWorkThread::Cleanup(long *pnResult)
{
	TRawMsg EndMsg;						
	INIT_MSG_HEADER(&EndMsg);			
	EndMsg.type = MT_TERMINATE;				
	TRACE_LOG("[_Debug]: CWorkThread Cleanup() !");
	pRemoteMsgThreadTCPClient->CloseRemoteMsgThreadTCPClient();
	if(pRemoteAgent){						
		pRemoteAgent->SendMsg(&EndMsg); 
		TRACE_LOG("[_Debug]: pRemoteAgent->SendMsg(&EndMsg) !");
	}
	bCloseFlag = 1;
}

BOOL CWorkThread::Close()
{
	TRawMsg EndMsg;						
	INIT_MSG_HEADER(&EndMsg);			
	EndMsg.type = MT_TERMINATE;	
	SendMsg(&EndMsg);
	TRACE_LOG("[_Debug]: CWorkThread close() !");
}

BOOL CWorkThread::IsClose()
{
	if(pRemoteMsgThreadTCPClient && (1==bCloseFlag))
	{
		if(TRUE == pRemoteMsgThreadTCPClient->IsClose()){
			OSSleep(5);
			delete pRemoteMsgThreadTCPClient;
		}
	} 
	return bCloseFlag;
}

BOOL CWorkThread::TaskExecuteInit()
{
	// create dir.
	DIR *ResultFileDir;
	if( 1 < strlen(struTaskPackages.Filedirectory))
	{
		ResultFileDir = opendir(struTaskPackages.Filedirectory);
		if( NULL == ResultFileDir )
		{
			char path[256];
			sprintf(path,"%s/%llu",struTaskPackages.Filedirectory,struTaskPackages.InvokeID);
			char cmd[256];
			sprintf(cmd,"/bin/mkdir %s",struTaskPackages.Filedirectory);
			TRACE_LOG("cmd:%s",cmd);
			//OSExecCmd(cmd);
			system(cmd);
			OSSleep(1000);
		}
	}
	TaskRuleAnalysis();
	//Set the cycle time of query core 
	TRawMsgTimer.type = MSG_QUERY_CORE_TIMER;
	m_QueryCoreTimer.SetMessage(&TRawMsgTimer);
	switch(struTaskPackages.Gathertype)
	{
		case TimeSegment:
			m_QueryCoreTimer.SetTime(2*60000,TRUE);//two minutes
			break;
		case TimeDot:
			m_QueryCoreTimer.SetTime(struTaskPackages.Filefrequence*60000,TRUE);
			break;
		default:
			m_QueryCoreTimer.SetTime(2*60000,TRUE);//two minutes
			break;
	}
	TRACE_LOG("[_Debug]: after workthread TaskExecuteInit()----CC.size()=%u,MDN.size()=%u",StruHandleObjects.MapCC.size(),StruHandleObjects.VectorMDN_IMSI.size());
	return TRUE;
}
U8	CWorkThread::MatchString(const char* str)
{
	if(!strcmp(str,"MDN"))
	{
		return FL_MDN;	
	}
	if(!strcmp(str,"IMSI"))
	{
		return FL_IMSI;	
	}
	if(!strcmp(str,"CC"))
	{
		return FL_CC;	
	}
	if(!strcmp(str,"PowerState"))
	{
		return FL_PowerState;	
	}
	if(!strcmp(str,"BusyState"))
	{
		return FL_BusyState;	
	}
	if(!strcmp(str,"PosFlag"))
	{
		return FL_PosFlag;
	}
	if(!strcmp(str,"CurTime"))
	{
		return FL_CurTime;	
	}
	if(!strcmp(str,"EventID"))
	{
		return FL_EventID;	
	}
	if(!strcmp(str,"LAT"))
	{
		return FL_LAT;	
	}
	if(!strcmp(str,"LON"))
	{
		return FL_LON;	
	}
	return 0;
}

U8 CWorkThread::GetFieldID(strings &strs_object,UserDefineRule* RuleStore,U8 RuleType)
{
	strings::iterator itStrs;
	U8	FieldNums = 0,TotalNum = 0,FieldNum;
	
	itStrs = strs_object.begin();
	switch(RuleType)
	{
		case AES_Encrypt:
			while(itStrs != strs_object.end())
			{
				if( 0 < (FieldNum = MatchString(itStrs->c_str()))){
					((StruEncryptAES*)RuleStore)->FieldID[FieldNums++] = FieldNum;
					((StruEncryptAES*)RuleStore)->IsAes[FieldNum] = TRUE;
					((StruEncryptAES*)RuleStore)->ResPlace[FieldNum] = TotalNum;
					TotalNum++;
				}
				itStrs++;
			}				
		break;
		case Replace_Encrypt:
			while(itStrs != strs_object.end())
			{
				if( 0 < (FieldNum = MatchString(itStrs->c_str()))){
					((StruEncryptReplace*)RuleStore)->FieldID[FieldNums++] = FieldNum;
					((StruEncryptReplace*)RuleStore)->IsRep[FieldNum] = TRUE;
					((StruEncryptReplace*)RuleStore)->ResPlace[FieldNum] = TotalNum;
					TotalNum++;
				}
				itStrs++;
			}	
		break;
		case Fetch_Field:
			while(itStrs != strs_object.end())
			{
				if( 0 < (FieldNum = MatchString(itStrs->c_str()))){
					((StruFetch*)RuleStore)->FieldID[FieldNums++] = FieldNum;
					TotalNum++;
				}
				itStrs++;
			}			
		break;
		case Filter_Field:
			while(itStrs != strs_object.end())
			{
				if( 0 < (FieldNum = MatchString(itStrs->c_str()))){
					((StruFilter*)RuleStore)->FieldID[FieldNums++] = FieldNum;
					TotalNum++;
				}
				itStrs++;
			}			
		break;
		default:
		break;
	}
	return TotalNum;
}

BOOL CWorkThread::TaskRuleAnalysis()
{
	strings Strs,StrsChild,StrsFilter;
	strings::iterator itStrs,itCC,itMDN;
	I32 iNum,iMedian;
	string strCC;
	
	divide_string(struTaskPackages.HandleObjects.c_str(),Strs,";");
	itStrs = Strs.begin();
	itCC = Strs.end();
	itMDN = Strs.end();
	while(itStrs != Strs.end())
	{
		if(!strcmp(itStrs->c_str(),"C"))
		{
			StruHandleObjects.ObjectsFlag |= 0x01;
			itCC = ++itStrs;
			continue;
		}
		if(!strcmp(itStrs->c_str(),"_C"))
		{
			itCC = Strs.end();
		}
		if(!strcmp(itStrs->c_str(),"M"))
		{
			StruHandleObjects.ObjectsFlag |= 0x02;
			itMDN = ++itStrs;
			continue;
		}
		if(!strcmp(itStrs->c_str(),"_M"))
		{
			itMDN = Strs.end();
		}
		
		if(Strs.end() != itCC)
		{
			StruHandleObjects.MapCC.insert(CCStatsResultMap::value_type(*itCC++,pair<U64,U64>(0,0)));
		}
		if(Strs.end() != itMDN)
		{
			StruHandleObjects.VectorMDN_IMSI.push_back(atol(itMDN->c_str()));
			itMDN++;
		}
		itStrs++;
	}	
	//judge core query type
	if( 1 == struTaskPackages.Isphone)
	{
		iCoreQueryType = QueryMDNs_Status;
	}else
	{
		iCoreQueryType = QueryCC_Phone;
	}	
	//Rule transfer
	if(1 == struTaskPackages.TaskRule.IsEncrypt)
	{
		if( (1 == struTaskPackages.TaskRule.Type) || (3 == struTaskPackages.TaskRule.Type)){
			divide_string(struTaskPackages.TaskRule.AESColum,Strs,",");
			if(0 < Strs.size()){
				RuleID |= AES_Encrypt;
				StruAesRule.TotalNums = GetFieldID(Strs,&StruAesRule,AES_Encrypt);
			}
		}
		if( (2 == struTaskPackages.TaskRule.Type) || (3 == struTaskPackages.TaskRule.Type) ){
			divide_string(struTaskPackages.TaskRule.Recolum,Strs,",");
			if(0 < Strs.size()){
				RuleID |= Replace_Encrypt;
				StruReplaceRule.TotalNums = GetFieldID(Strs,&StruReplaceRule,Replace_Encrypt);
				divide_string(struTaskPackages.TaskRule.StartPostion,Strs,",");
				itStrs = Strs.begin();
				iNum = 0;
				while(StruReplaceRule.TotalNums > iNum)
				{
					if(itStrs !=  Strs.end()){
						StruReplaceRule.StartAddr[iNum] = atoi(itStrs->c_str());
						itStrs++;
					}else{
						StruReplaceRule.StartAddr[iNum] = StruReplaceRule.StartAddr[Strs.size()-1];
					}
					if( 0 == StruReplaceRule.StartAddr[iNum])
						StruReplaceRule.StartAddr[iNum] = 1;
					iNum++;
				}
				divide_string(struTaskPackages.TaskRule.EndPostion,Strs,",");
				itStrs = Strs.begin();
				iNum = 0;
				while(StruReplaceRule.TotalNums > iNum)
				{
					if(itStrs !=  Strs.end()){
						StruReplaceRule.EndAddr[iNum] = atoi(itStrs->c_str());
						itStrs++;
					}else{
						StruReplaceRule.EndAddr[iNum] = StruReplaceRule.EndAddr[Strs.size()-1];
					}
					if( 0 == StruReplaceRule.EndAddr[iNum])
						StruReplaceRule.EndAddr[iNum] = 1;
					iNum++;
				}
				divide_string(struTaskPackages.TaskRule.To,Strs,",");
				itStrs = Strs.begin();
				iNum = 0;
				while( StruReplaceRule.TotalNums > iNum)
				{
					if(itStrs !=  Strs.end()){
						StruReplaceRule.To[iNum++] = itStrs->at(0);
						itStrs++;
					}else{
						StruReplaceRule.To[iNum++] = StruReplaceRule.To[Strs.size()-1];
					}
				}
				iNum = 0;
				while(MAX_FIELDS_NUMS > iNum)
				{
					if( StruReplaceRule.StartAddr[iNum] > StruReplaceRule.EndAddr[iNum])
					{
						iMedian = StruReplaceRule.StartAddr[iNum];
						StruReplaceRule.StartAddr[iNum] = StruReplaceRule.EndAddr[iNum];
						StruReplaceRule.EndAddr[iNum] = iMedian;
					}
					iNum++;
				}
			}
		}
	}
	divide_string(struTaskPackages.TaskRule.Fetch,Strs,",");
	if(0 < Strs.size())
	{
		RuleID |= Fetch_Field;
		StruFetchRule.TotalNums = GetFieldID(Strs,&StruFetchRule,Fetch_Field);
	}
	divide_string(struTaskPackages.TaskRule.Filter,Strs,";");
	if(0 < Strs.size())
	{
		RuleID |= Filter_Field;
		itStrs = Strs.begin();
		StrsFilter.clear();
		iNum = 0;
		while(itStrs != Strs.end())
		{
			divide_string(itStrs->c_str(),StrsChild,"=");
			StrsFilter.push_back(StrsChild.at(0));
			StruFilterRule.FilterVaule[iNum++] = atol(StrsChild.at(1).c_str());
			itStrs++;
		}	
		StruFilterRule.TotalNums = GetFieldID(StrsFilter,&StruFilterRule,Filter_Field);
	}
	
	return TRUE;
}

FILE* CWorkThread::PrepairFile(U64 invokeid,char* pFileName,char* pFolderName,U8 IsCacheFile)
{
	FILE* fp = NULL;
	DIR * dir = NULL;
	struct timeval tnow;
	struct tm tmlocal; 
	char full_path[256];
	char File_Folder[256];
	char cmd[256];
	
	TUGetTime(CurTime);
	memset(full_path,0,256);
	memset(File_Folder,0,256);
	memset(cmd,0,256);
	if( NULL == pFolderName)
	{
		sprintf(File_Folder,"%s/%llu",struTaskPackages.Filedirectory,invokeid);
		sprintf(cmd,"/bin/mkdir %s",File_Folder);
		if(NULL == (dir = opendir(File_Folder))){
			TRACE_LOG("[_Debug]: create file_Dir %s",File_Folder);
			system(cmd);/*OSExecCmd(cmd);*/OSSleep(100);
		}
		sprintf(pFileName, "%llu/SHOIDD_AreaSMS_%04d%02d%02d%02d%02d%02d.txt",
		invokeid,CurTime.year,CurTime.month,CurTime.day,CurTime.hour,CurTime.minute,CurTime.second);
	}
	else
	{		
		sprintf(File_Folder,"%s/%llu",struTaskPackages.Filedirectory,invokeid);
		sprintf(cmd,"/bin/mkdir %s",File_Folder);
		if(NULL == (dir = opendir(File_Folder))){
			TRACE_LOG("[_Debug]: create file_Dir %s",File_Folder);
			system(cmd);/*OSExecCmd(cmd);*/OSSleep(100);
		}
		sprintf(pFileName, "%s/SHOIDD_AreaSMS_%04d%02d%02d%02d%02d%02d.txt",
		pFolderName,CurTime.year,CurTime.month,CurTime.day,CurTime.hour,CurTime.minute,CurTime.second);
	}
	if(TRUE == IsCacheFile)
	{			
		sprintf(File_Folder,"%s/%llu/CacheFiles",struTaskPackages.Filedirectory,invokeid);
		sprintf(cmd,"/bin/mkdir %s",File_Folder);
		if(NULL == (dir = opendir(File_Folder))){
			TRACE_LOG("[_Debug]: create file_Dir %s",File_Folder);
			system(cmd);/*OSExecCmd(cmd);*/OSSleep(100);
		}
		sprintf(pFileName, "%llu/CacheFiles/%llu_%04d%02d%02d%02d%02d%02d.txt",invokeid,
		invokeid,CurTime.year,CurTime.month,CurTime.day,CurTime.hour,CurTime.minute,CurTime.second);
	}
	sprintf(full_path,"%s/%s",struTaskPackages.Filedirectory,pFileName);
	//TRACE_LOG("[_Debug]: task:%llu create file:%s.",invokeid,full_path);
	fp = fopen(full_path, "a");
	if(NULL == fp)
		TRACE_LOG("[_Error]: fopen() %s fail !",full_path);
	return fp;
}

void CWorkThread::QueryCore()
{
	strings::iterator itStrs;
	CCStatsResultMap::iterator itMapCC;
	vector<U64>::iterator itMDN_IMSI_Vec;
	I32 iObjectsID,iFilterNum;
	TRACE_LOG("[_Debug]: InvokeID(%llu) the workthread is send query msg !   iCoreQueryType=%d,StruHandleObjects.MapCC.size():%u",struTaskPackages.InvokeID,iCoreQueryType,StruHandleObjects.MapCC.size());
	if( !CheckTime())
	{
		return;
	}
	switch(iCoreQueryType)
	{
		case QueryMDN_Status:
		case QueryIMSI_Status:
		{
			TRTQueryMsg QueryMsg;
			memset(&QueryMsg,0,sizeof(TRTQueryMsg));
			INIT_MSG_HEADER(&QueryMsg);
			QueryMsg.type = MSG_TYPE_OIDDCORE_MDNBREQ;
			QueryMsg.InvokeID = struTaskPackages.InvokeID;
			itMDN_IMSI_Vec = StruHandleObjects.VectorMDN_IMSI.begin();
			while( itMDN_IMSI_Vec != StruHandleObjects.VectorMDN_IMSI.end() )
			{
				QueryMsg.MDNIMSI = *itMDN_IMSI_Vec;
				if(pRemoteAgent)
					pRemoteAgent->SendMsg(&QueryMsg);
				itMDN_IMSI_Vec++;
			}
		}
		break;
		case QueryCC_Phone:
		{
			TCCQueryMsg2 QueryMsg;
			memset(&QueryMsg,0,sizeof(TCCQueryMsg2));
			INIT_MSG_HEADER(&QueryMsg);
			QueryMsg.type = MSG_TYPE_CCQUERY2_MSG;
			QueryMsg.InvokeID = struTaskPackages.InvokeID;

			QueryMsg.PosFlag = 2;
			iFilterNum = 0;//TRACE_LOG("[_Debug]: StruFilterRule.TotalNums=%u; StruHandleObjects.MapCC.size()=%d",StruFilterRule.TotalNums,StruHandleObjects.MapCC.size());
			while(StruFilterRule.TotalNums > iFilterNum)
			{
				if( (StruFilterRule.FieldID[iFilterNum] == FL_PosFlag) )
				{
					if(0 == StruFilterRule.FilterVaule[iFilterNum])
					{
						QueryMsg.PosFlag = 0;
					}
					else if(1 == StruFilterRule.FilterVaule[iFilterNum])
					{
						QueryMsg.PosFlag = 1;
					}
				}
				iFilterNum++;
			}
			
			itMapCC = StruHandleObjects.MapCC.begin();
			while( itMapCC != StruHandleObjects.MapCC.end() )
			{
				memset(QueryMsg.CellCode,0,8);
				strcpy(QueryMsg.CellCode,itMapCC->first.c_str());
				//TRACE_LOG("[_Debug]: QueryCore Send Msg, QueryMsg.CellCode:%s",QueryMsg.CellCode);
				if(pRemoteAgent){
					pRemoteAgent->SendMsg(&QueryMsg);}
				itMapCC++;
			}
		}	
		break;
		case QueryMDNs_Status:
		{
			char MDNs_buf[5000];
			int i,j,index;
			U32 mdn_count,steps;
			TCoreAddMDNsMsg *pQueryMsg = (TCoreAddMDNsMsg*)MDNs_buf;
			memset(pQueryMsg,0,sizeof(MDNs_buf));
			pQueryMsg->type = MSG_TYPE_OIDDCORE_ADDMDNS;
			pQueryMsg->ActionType = 1;
			
			
			mdn_count = StruHandleObjects.VectorMDN_IMSI.size();
			steps = (mdn_count-1) / 500;
			//TRACE_LOG("[_Debug]: mdn_count:%u",mdn_count);

			pQueryMsg->len = sizeof(TCoreAddMDNsMsg) - sizeof(TRawMsg);
			pQueryMsg->len += 8*500;
			pQueryMsg->Count = 500;
			index = 0;
			
			for(j=0;j<steps;j++)
			{
				for(i=0;i<500;i++)
				{
					pQueryMsg->MDNs[i] = StruHandleObjects.VectorMDN_IMSI[index];
					index++;
				}
				if(pRemoteAgent)
					pRemoteAgent->SendMsg(pQueryMsg);
				//TRACE_LOG("MDN count:%d,len:%d,",pQueryMsg->Count,pQueryMsg->len);
			}
			// and last message will set tailflag, and figures count domain.
			for(i=0;index<mdn_count;index++,i++)
			{
				pQueryMsg->MDNs[i] = StruHandleObjects.VectorMDN_IMSI[index];
			}
			pQueryMsg->len = sizeof(TCoreAddMDNsMsg) - sizeof(TRawMsg);
			pQueryMsg->len += 8*i;
			pQueryMsg->Count=i;
			if(pRemoteAgent){
				pRemoteAgent->SendMsg(pQueryMsg);
				/*TRACE_LOG("[_Debug]: case:QueryMDNs_Status  Send out:len=%u,ActionType=%u,Count=%u,MDNs[0]=%llu,MDNs[1]=%llu;StruFilterRule.TotalNums=%u; StruHandleObjects.MapCC.size()=%d",
					pQueryMsg->len,pQueryMsg->ActionType,pQueryMsg->Count,pQueryMsg->MDNs[0],pQueryMsg->MDNs[1],
					StruFilterRule.TotalNums,StruHandleObjects.MapCC.size());*/
			}
		}
		break;
		default:
		break;
	}
}

void CWorkThread::ClearStatsResult()
{
	MapCCiterator itMapCC;
	itMapCC = StruHandleObjects.MapCC.begin();
	while(itMapCC != StruHandleObjects.MapCC.end() )
	{
		itMapCC->second.first = 0;
		itMapCC->second.second = 0;
		itMapCC++;
	};
}

BOOL CWorkThread::IsExistInCCMap(const char * pchar,MapCCiterator &itMap)
{
	MapCCiterator itCCMap;
	itCCMap = StruHandleObjects.MapCC.find(pchar);
	if(itCCMap != StruHandleObjects.MapCC.end())
	{
		itMap = itCCMap;//************&的使用是否可以**********(~_~)(*~_~*)
		return TRUE;
	}
	return FALSE;
}

void CWorkThread::GetStruFetchRule(StruFetch* pStru)
{
	pStru = &StruFetchRule;
}

void CWorkThread::GetstruTaskPackage(TaskExecutePackages* pTaskPackage)
{	
	pTaskPackage = &struTaskPackages;
}

void CWorkThread::GetStruQueryObject(StruQueryObjects* pStru)
{
	pStru = &StruHandleObjects;
}

I32 CWorkThread::GetQueryType()
{
	return iCoreQueryType;
}
I32 CWorkThread::GetRuleID()
{
	return RuleID;
}

















CStatsDotThread::CStatsDotThread()
{
	m_bEnableQueryFlag = 0;
	m_CcLonLatMap.clear();
}

CStatsDotThread::~CStatsDotThread()
{
	;
}

BOOL CStatsDotThread::OnMsg(TRawMsg * msg,IMsg * remote_src)
{
	if( MSG_CLOSE_TASK == msg->type )
	{
		Close();
	}
	else if(MSG_HEART_BEAT_TIMER == msg->type)
	{
		HeartBeat();
	}
	else if(MSG_EXECUTE_TASK_INIT == msg->type)
	{
		if(TRUE == TaskExecuteInit())
		{
			TRACE_LOG("[inform]: Will query core agent,CStatsDotThread Initialize() is success!");	
			QueryCore();
		}			
		AddTimer(&m_QueryCoreTimer);
	}
	else if(MSG_LON_LAN_QUERY == msg->type)
	{
		TRawMsg LonLatMsg;
		INIT_MSG_HEADER(&LonLatMsg);
		LonLatMsg.type = MSG_LON_LAN_QUERY;
		if(pRemoteAgent){
			TRACE_LOG("[inform]: CStatsDotThread InvokeID(%llu) the Core agent has connect !",struTaskPackages.InvokeID);
			pRemoteAgent->SendMsg(&LonLatMsg);
		}
		else{
			OSSleep(1000);
			TRACE_LOG("[warning]: CStatsDotThread InvokeID(%llu) the Core agent is not connect !",struTaskPackages.InvokeID);
			SendMsg(&LonLatMsg);
		}
	}
	else if(MSG_LAN_LON_RESPONSE == msg->type)
	{
		LatLonMsg* pMsg = (LatLonMsg*)msg;
		LonLatStruct *pStru = pMsg->result;
		CC_LonLatMap::iterator itCCLonLatmap;
		U32 iNums = 0;
		//TRACE_LOG("[_Debug]: CStatsDotThread get the LON/LAT result msg,pMsg->Count:%u",pMsg->Count);
		
		while(pMsg->Count > iNums){//TRACE_LOG("[_Debug]: CStatsDotThread pStru->CellCode:%s ;len:%u",pStru->CellCode,pMsg->len);
			itCCLonLatmap = m_CcLonLatMap.find(pStru->CellCode);
			if(itCCLonLatmap != m_CcLonLatMap.end()){
				//TRACE_LOG("[_Debug]: CStatsDotThread insert LON/LAT(%s,%s) in m_CcLonLatMap",pMsg->result[0].Lon,pMsg->result[0].Lat);
				itCCLonLatmap->second.first.assign(pStru->Lon);
				itCCLonLatmap->second.second.assign(pStru->Lat);
			}
			pStru++;iNums++;
		}
		if((1 == pMsg->OverFlag) && !m_bEnableQueryFlag){
			TRawMsg querymsg;
			INIT_MSG_HEADER(&querymsg);
			querymsg.type = MSG_QUERY_CORE_TIMER;
			m_bEnableQueryFlag = 1;
			SendMsg(&querymsg);
		}
	}
	else if(MSG_QUERY_CORE_TIMER == msg->type)
	{
		QueryCore();
	}
	else if(MSG_TYPE_CCQUERYRSLT2_MSG == msg->type)
	{
		//TRACE_LOG("[_Debug]: CStatsDotThreadg get the return msg of OiddCore CC query !");
		HandleResponseData(msg);
	}
	else if(MT_SESSION_CONNECT == msg->type)
	{
		TRACE_LOG("Session connected,    name = '%s'", ((TSessionConnect*)msg)->name);
		if( !strcmp(((TSessionConnect*)msg)->agent_name,AGENT_NAME_OIDD_CORE))
		{TRACE_LOG("[_Debug]: pRemoteAgent->name = '%s'", ((TSessionConnect*)msg)->agent_name);
			pRemoteAgent = ((TSessionConnect*)msg)->session;
		}
	}
	else if(MT_SESSION_DISCONNECT == msg->type)
	{
		TRACE_LOG("Session disconnected,    name = '%s'", ((TSessionConnect*)msg)->name);
		if( !strcmp(((TSessionConnect*)msg)->agent_name,AGENT_NAME_OIDD_CORE))
		{
			pRemoteAgent = NULL;
		}
	}
	else
	{
		TRACE_LOG("Session not Know,    name = '%s'", ((TSessionConnect*)msg)->name);
	}
	
	return TRUE;
}


BOOL CStatsDotThread::TaskExecuteInit()
{
	int iNum = 0,i = 0,iCcNum = 0;
	char buffer[CHAR_MAX_TASK_MSG_PACKAGES];
	LatLonMsg *pLonLatMsg = (LatLonMsg*)buffer;
	CCStatsResultMap::iterator itCCMap;
	char strCcName[64];
	
	CWorkThread::TaskExecuteInit();
	memset(buffer,0,CHAR_MAX_TASK_MSG_PACKAGES);
	m_CcLonLatMap.clear();
	while( StruFetchRule.TotalNums > iNum)
	{
		if( (FL_LAT == StruFetchRule.FieldID[iNum]) || (FL_LON == StruFetchRule.FieldID[iNum]))
		{
			itCCMap = StruHandleObjects.MapCC.begin();
			while( itCCMap != StruHandleObjects.MapCC.end() )
			{
				i = itCCMap->first.find_first_of(",");
				if (i != string::npos)
				{	
					memset(strCcName,0,64);
					memcpy(strCcName,itCCMap->first.c_str(),i);
					TRACE_LOG("[_Debug]: m_CcLonLatMap insert strCcName is:%s",strCcName);
					m_CcLonLatMap.insert(CC_LonLatMap::value_type(strCcName,pair<string,string>("","")));
					pLonLatMsg->Count++;//[_Debug]
					if(51 > pLonLatMsg->Count)//[_Debug]
						strcpy(pLonLatMsg->result[iCcNum++].CellCode,strCcName);//[_Debug]
					else
						pLonLatMsg->Count--;
				}
				itCCMap++;
			}
			pLonLatMsg->type = MSG_LON_LAN_QUERY;	
			pLonLatMsg->len = sizeof(LatLonMsg) - sizeof(TRawMsg) + iCcNum*sizeof(LonLatStruct);//[_Debug]
			pLonLatMsg->Count = iCcNum;//[_Debug]
			if(pRemoteAgent){TRACE_LOG("[_Debug]: CStatsDotThread send query LAT/LON msg !,Count=%u",pLonLatMsg->Count);
				pRemoteAgent->SendMsg(pLonLatMsg);
			}else
			{
				OSSleep(1500);TRACE_LOG("[_Debug]: CStatsDotThread core agent is not connect !");
				SendMsg(pLonLatMsg);
			}
			return FALSE;
		}
		iNum++;
	}
	m_bEnableQueryFlag = 1;
	TRACE_LOG("[_Debug]: CStatsDotThread TaskExecuteInit over !");
	
	return TRUE;
}

void CStatsDotThread::QueryCore()
{
	if(m_bEnableQueryFlag && pRemoteAgent){
		if(0 != m_CCnums){
			TRACE_LOG("[_Error]: CStatsSegmentThread m_CCnums=%llu, so last Handleing is not over !",m_CCnums);
			if(NULL != m_CoreReturn_pf){
				fflush(m_CoreReturn_pf);fclose(m_CoreReturn_pf);
			}
			m_CCnums = 0;
		}
		CWorkThread::QueryCore();
	}
	else{
		TRawMsg QueryCoreMsg;
		INIT_MSG_HEADER(&QueryCoreMsg);
		QueryCoreMsg.type = MSG_QUERY_CORE_TIMER;
		OSSleep(1000);
		TRACE_LOG("[_Error]: CStatsDotThread the Core agent is not connect !");
		SendMsg(&QueryCoreMsg);
	}	
}

BOOL CStatsDotThread::HandleResponseData(TRawMsg* msg)
{
	CCStatsResultMap BSMap;
	CCStatsResultMap::iterator itBSMap;
	CCStatsResultMap::iterator itMapCC;
	CC_LonLatMap::iterator itLonLat;
	int	GradeAllFlag = 0;	
	U64 StatsNum,StatsNum1;
	int iResultNum;
	U64 iColNums;
	strings strsBS;
	
	switch(iCoreQueryType)
	{
		case QueryCC_Phone:
		{
			TCCQueryRSLTMsg2 *pResponseMsg = (TCCQueryRSLTMsg2*)msg;
			
			if(NULL == m_CoreReturn_pf){
				memset(file_name,0,128);
				m_CoreReturn_pf = PrepairFile(pResponseMsg->InvokeID,file_name);
				if(NULL == m_CoreReturn_pf){
					TRACE_LOG("[_error]: PrepairFile return NULL !");
					return FALSE;
				} 
			}
			//statistic result
			itMapCC = StruHandleObjects.MapCC.find(pResponseMsg->CellCode);
			if(itMapCC == StruHandleObjects.MapCC.end())
				return FALSE;
			m_pUserState2 = pResponseMsg->states;
			if( Filter_Field&RuleID ){//need handle filter rule
				iResultNum = pResponseMsg->Count;
				while( 0 < iResultNum--)
				{
					if(TRUE == Filter(m_pUserState2)){
						if(!(pResponseMsg->PosFlag)){
							itMapCC->second.first += 1;
						}
						else{
							itMapCC->second.second += 1;
						}
					}
					m_pUserState2++;
				}
			}
			else{
				iResultNum = pResponseMsg->Count;
				while( 0 < iResultNum--)
				{
					if(!(pResponseMsg->PosFlag)){
						itMapCC->second.first += 1;
					}
					else{
						itMapCC->second.second += 1;
					}
					m_pUserState2++;
				}
			}
			//TRACE_LOG("[_Debug]: StatsAllNum handle Result _1_!");
			if((1 == pResponseMsg->TailFlag) && (++m_CCnums == StruHandleObjects.MapCC.size())){
				//TRACE_LOG("[_Debug]: StatsAllNum handle Result _2_! struTaskPackages.Resulttype:%d",struTaskPackages.Resulttype);
				if( StatsAllNum == struTaskPackages.Resulttype ){
					//TRACE_LOG("[_Debug]: StatsAllNum handle Result _3_!");
					switch(struTaskPackages.Grade)
					{
						case Grade_All:
							GradeAllFlag = 1;
						case Grade_Area:
							StatsNum = 0;
							itMapCC = StruHandleObjects.MapCC.begin();
							while(itMapCC !=  StruHandleObjects.MapCC.end())
							{
								StatsNum += itMapCC->second.first;
								StatsNum += itMapCC->second.second;
								itMapCC++;
							}
							fprintf(m_CoreReturn_pf,"%llu %llu\n",struTaskPackages.InvokeID,StatsNum);
							if(!GradeAllFlag){
								break;
							}
						case Grade_BasicStation:
						{						
							StatsNum = 0;
							BSMap.clear();
							itMapCC = StruHandleObjects.MapCC.begin();
							while(itMapCC != StruHandleObjects.MapCC.end())
							{
								divide_string(itMapCC->first.c_str(),strsBS,",");
								itBSMap = BSMap.find(strsBS.at(0));
								if(itBSMap != BSMap.end()){
									itBSMap->second.first += itMapCC->second.first;
									itBSMap->second.second += itMapCC->second.second;
								}else{
									BSMap.insert(CCStatsResultMap::value_type(strsBS.at(0).c_str(),pair<U64,U64>(itMapCC->second.first,itMapCC->second.second)));
								}
								itMapCC++;	
							}
							itBSMap = BSMap.begin();
							if( Fetch_Field&RuleID ){
								while(itBSMap !=  BSMap.end())
								{	
									iColNums = 0;
									fprintf(m_CoreReturn_pf,"%s ",itBSMap->first.c_str());
									while( StruFetchRule.TotalNums > iColNums)
									{
										switch(StruFetchRule.FieldID[iColNums])
										{
											case FL_LON:
												itLonLat = m_CcLonLatMap.find(itBSMap->first.c_str());
												if(itLonLat != m_CcLonLatMap.end())
													fprintf(m_CoreReturn_pf,"%s ",itLonLat->second.first.c_str());
												else
													fprintf(m_CoreReturn_pf,"%s ","NoFind");
												break;
											case FL_LAT:
												itLonLat = m_CcLonLatMap.find(itBSMap->first.c_str());
												if(itLonLat != m_CcLonLatMap.end())
													fprintf(m_CoreReturn_pf,"%s ",itLonLat->second.second.c_str());
												else
													fprintf(m_CoreReturn_pf,"%s ","NoFind");
												break;
											default:
												break;
										}
										iColNums++;
									}
									fprintf(m_CoreReturn_pf,"%llu\n",itBSMap->second.first+itBSMap->second.second);
									itBSMap++;	
								}
							}
							else{
								while(itBSMap !=  BSMap.end())
								{
									fprintf(m_CoreReturn_pf,"%s %llu\n",itBSMap->first.c_str(),itBSMap->second.first+itBSMap->second.second);
									itBSMap++;
								}									
							}
						}
							if(!GradeAllFlag){
								break;
							}
						case Grade_Section://不支持，索取经纬度字段 **************************************(~_~)(*~_~*)
							itMapCC = StruHandleObjects.MapCC.begin();
							while(itMapCC !=  StruHandleObjects.MapCC.end())
							{
								fprintf(m_CoreReturn_pf,"%s %llu\n",itMapCC->first.c_str(),itMapCC->second.first+itMapCC->second.second);
								itMapCC++;
							}
							if(!GradeAllFlag){
								break;
							}
						default:
						break;
					}
				}
				else if( StatsUnfoldNum == struTaskPackages.Resulttype )
				{//TRACE_LOG("[_Debug]: StatsAllNum handle Result __StatsUnfoldNum__!");
					switch(struTaskPackages.Grade)
					{
						case Grade_All:
							GradeAllFlag = 1;
						case Grade_Area:
							StatsNum = 0;
							StatsNum1 = 0;
							itMapCC = StruHandleObjects.MapCC.begin();
							while(itMapCC !=  StruHandleObjects.MapCC.end())
							{
								StatsNum += itMapCC->second.first;
								StatsNum1 += itMapCC->second.second;
								itMapCC++;
							}
							fprintf(m_CoreReturn_pf,"%llu %llu %llu\n",struTaskPackages.InvokeID,StatsNum,StatsNum1);						
							if(!GradeAllFlag){
								break;
							}
						case Grade_BasicStation:
						{						
							StatsNum = 0;
							BSMap.clear();
							itMapCC = StruHandleObjects.MapCC.begin();
							while(itMapCC != StruHandleObjects.MapCC.end())
							{
								divide_string(itMapCC->first.c_str(),strsBS,",");
								itBSMap = BSMap.find(strsBS.at(0).c_str());
								if(itBSMap != BSMap.end()){
									itBSMap->second.first += itMapCC->second.first;
									itBSMap->second.second += itMapCC->second.second;
								}else{
									BSMap.insert(CCStatsResultMap::value_type(strsBS.at(0).c_str(),pair<U64,U64>(itMapCC->second.first,itMapCC->second.second)));
								}
								itMapCC++;	
							}
							itBSMap = BSMap.begin();
							if( Fetch_Field&RuleID ){
								while(itBSMap !=  BSMap.end())
								{	
									fprintf(m_CoreReturn_pf,"%s ",itBSMap->first.c_str());
									iColNums = 0;
									while( StruFetchRule.TotalNums > iColNums)
									{
										switch(StruFetchRule.FieldID[iColNums])
										{
											case FL_LON:
												itLonLat = m_CcLonLatMap.find(itBSMap->first.c_str());
												if(itLonLat != m_CcLonLatMap.end())
													fprintf(m_CoreReturn_pf,"%s ",itLonLat->second.first.c_str());
												else
													fprintf(m_CoreReturn_pf,"%s ","NoFind");
												break;
											case FL_LAT:
												itLonLat = m_CcLonLatMap.find(itBSMap->first.c_str());
												if(itLonLat != m_CcLonLatMap.end())
													fprintf(m_CoreReturn_pf,"%s ",itLonLat->second.second.c_str());
												else
													fprintf(m_CoreReturn_pf,"%s ","NoFind");
												break;
											default:
												break;
										}
										iColNums++;
									}
									fprintf(m_CoreReturn_pf," %llu %llu\n",itBSMap->second.first,itBSMap->second.second);
									itBSMap++;	
								}
							}
							else{
								while(itBSMap !=  BSMap.end())
								{
									fprintf(m_CoreReturn_pf,"%s %llu %llu\n",itBSMap->first.c_str(),itBSMap->second.first,itBSMap->second.second);
									itBSMap++;
								}									
							}
						}
							if(!GradeAllFlag){
								break;
							}
						case Grade_Section://不支持，索取经纬度字段 **************************************(~_~)(*~_~*)
							itMapCC = StruHandleObjects.MapCC.begin();
							while(itMapCC !=  StruHandleObjects.MapCC.end())
							{
								fprintf(m_CoreReturn_pf,"%s %llu %llu\n",itMapCC->first.c_str(),itMapCC->second.first,itMapCC->second.second);
								itMapCC++;
							}
							if(!GradeAllFlag){
								break;
							}
						default:
						break;
					}
				}
				fflush(m_CoreReturn_pf);fclose(m_CoreReturn_pf);
				m_CoreReturn_pf = NULL;
				itMapCC = StruHandleObjects.MapCC.begin();
				while(itMapCC != StruHandleObjects.MapCC.end() )
				{
					itMapCC->second.first = 0;
					itMapCC->second.second = 0;
					itMapCC++;
				}
			}
		}
		break;
		//Reserved interface
		/*case QueryIMSI_Status:			
		case QueryMDN_Status:
			TRTQueryMsg	*pQueryMsg = (TRTQueryMsg*)msg;
		break;*/
		default:
		break;
	}
	return TRUE;
}
BOOL CStatsDotThread::Filter(TUserState2* pstru)
{
	int i = 0;
	while( StruFilterRule.TotalNums > i)
	{
		switch(StruFilterRule.FieldID[i])
		{
			case FL_PowerState:
				if(pstru->PowerState != StruFilterRule.FilterVaule[i])
					return FALSE;
				break;
			case FL_BusyState:
				if(pstru->BusyState != StruFilterRule.FilterVaule[i])
					return FALSE;
				break;
			case FL_EventID:
				if(pstru->EventID != StruFilterRule.FilterVaule[i])
					return FALSE;
				break;
			default:
			break;
		}
		i++;
	}
	return TRUE;
}



//统计时间段里基站下的手机号码数量
CStatsSegmentThread::CStatsSegmentThread()
{
	m_bEnableQueryFlag = 0;
	m_bCollectThreadliveFlag = 0;
}

CStatsSegmentThread::~CStatsSegmentThread()
{
	;
}

BOOL CStatsSegmentThread::OnMsg(TRawMsg * msg,IMsg * remote_src)
{
	if( MSG_CLOSE_TASK == msg->type )
	{
		m_CollectThread.Close();
		Close();
	}
	else if(MSG_HEART_BEAT_TIMER == msg->type)
	{
		if( (!CheckTime()) && (1 == m_bCollectThreadliveFlag)){
			if( 0 == m_CacheFileSet.size()){
				m_CollectThread.Close();
			}
		}
		else{
			if(0 == m_bCollectThreadliveFlag){
				if(FALSE ==(m_bCollectThreadliveFlag = m_CollectThread.Start()) ){
					TRACE_LOG("[error]_: the StatsSegment Collect Thread start() False!");
					return FALSE;
				}
			}
		}
		HeartBeat();
	}
	else if(MSG_EXECUTE_TASK_INIT == msg->type)
	{
		if(TRUE == TaskExecuteInit())
		{
			TRACE_LOG("[inform]: Will query core agent,CStatsSegmentThread Initialize() is success!");
			QueryCore();
		}
		AddTimer(&m_QueryCoreTimer);
	}
	else if(MSG_LON_LAN_QUERY == msg->type)
	{
		TRawMsg LonLatMsg;
		INIT_MSG_HEADER(&LonLatMsg);
		LonLatMsg.type = MSG_LON_LAN_QUERY;
		if(pRemoteAgent){
			TRACE_LOG("[inform]: CStatsSegmentThread the Core agent has connect !");
			pRemoteAgent->SendMsg(&LonLatMsg);
		}
		else{
			OSSleep(1000);
			TRACE_LOG("[warning]: CStatsSegmentThread the Core agent is not connect !");
			SendMsg(&LonLatMsg);
		}
	}
	else if(MSG_LAN_LON_RESPONSE == msg->type)
	{
		LatLonMsg* pMsg = (LatLonMsg*)msg;
		LonLatStruct* pStru = pMsg->result;
		CC_LonLatMap::iterator itCCLonLatmap;
		U32 iNums = pMsg->Count;
		
		while(iNums--){
			itCCLonLatmap = m_CcLonLatMap.find(pStru->CellCode);
			if(itCCLonLatmap != m_CcLonLatMap.end()){
				itCCLonLatmap->second.first.assign(pStru->Lon);
				itCCLonLatmap->second.second.assign(pStru->Lat);
			}
			pStru++;
		}
		if((1 == pMsg->OverFlag) && !m_bEnableQueryFlag){
			TRawMsg querymsg;
			INIT_MSG_HEADER(&querymsg);
			querymsg.type = MSG_QUERY_CORE_TIMER;
			m_bEnableQueryFlag = 1;
			SendMsg(&querymsg);
		}
	}
	else if(MSG_QUERY_CORE_TIMER == msg->type)
	{
		QueryCore();
	}
	else if(MSG_TYPE_CCQUERYRSLT2_MSG == msg->type)
	{
		//TRACE_LOG("[_Debug]: CStatsSegmentThread get MSG_TYPE_CCQUERYRSLT2_MSG, StruHandleObjects.MapCC.size():%d,Count:%u ",StruHandleObjects.MapCC.size(),((TCCQueryRSLTMsg2*)msg)->Count);
		HandleResponseData((TCCQueryRSLTMsg2*)msg);
	}
	else if(MT_SESSION_CONNECT == msg->type)
	{
		TRACE_LOG("Session connected,    name = '%s'", ((TSessionConnect*)msg)->name);
		if( !strcmp(((TSessionConnect*)msg)->agent_name,AGENT_NAME_OIDD_CORE))
		{
			pRemoteAgent = ((TSessionConnect*)msg)->session;
		}
	}
	else if(MT_SESSION_DISCONNECT == msg->type)
	{
		TRACE_LOG("Session disconnected,    name = '%s'", ((TSessionConnect*)msg)->name);
		if( !strcmp(((TSessionConnect*)msg)->agent_name,AGENT_NAME_OIDD_CORE))
		{
			pRemoteAgent = NULL;
		}
	}
	else
	{
		TRACE_LOG("Session not Know,    name = '%s'", ((TSessionConnect*)msg)->name);
	}
	
	return TRUE;
}

BOOL CStatsSegmentThread::TaskExecuteInit()
{
	int iFetNum = 0,i = 0;
	//LatLonMsg LonLatMsg;
	//CCStatsResultMap::iterator itCCMap;
	//string strCcName;
	I32 iDaySec;
	

	//set dest_time	
	TUGetTime(CurTime);
	DestTime.year = CurTime.year;
	DestTime.month = CurTime.month;
	DestTime.day = CurTime.day;
	iDaySec = struTaskPackages.Workstarttime + struTaskPackages.Filefrequence*60;
	DestTime.hour = iDaySec/3600;
	DestTime.minute = iDaySec%3600/60;
	DestTime.second = iDaySec%3600%60;
	
	
	CWorkThread::TaskExecuteInit();
	m_CollectThread.SetSegStatsThread(this);
	TRACE_LOG("[_Debug]: this address:%d,struTaskPackages:%d",this,&struTaskPackages);
	m_CollectThread.SetLoopTimeSec(struTaskPackages.Filefrequence*60);
	TRACE_LOG("[_Debug]: Judge CC is need LAT/LON !");
	/*while( StruFetchRule.TotalNums > iFetNum)
	{
		if( (FL_LAT == StruFetchRule.FieldID[iFetNum]) || (FL_LON == StruFetchRule.FieldID[iFetNum]))
		{
			m_CcLonLatMap.clear();
			itCCMap = StruHandleObjects.MapCC.begin();
			while( itCCMap != StruHandleObjects.MapCC.end() )
			{
				i = itCCMap->first.find_first_of(",");
				if (i != string::npos)
				{
					strCcName.assign(itCCMap->first.c_str(), 0, i);
					m_CcLonLatMap.insert(CC_LonLatMap::value_type(strCcName,pair<string,string>("","")));
					LonLatMsg.Count++;
				}
				itCCMap++;
			}
			TRACE_LOG("[_Debug]: Query the CC's LAT/LON !");
			INIT_MSG_HEADER(&LonLatMsg);
			LonLatMsg.type = MSG_LON_LAN_QUERY;
			if(pRemoteAgent){
				pRemoteAgent->SendMsg(&LonLatMsg);
			}else
			{
				OSSleep(1500);
				SendMsg(&LonLatMsg);
			}
			return FALSE;
		}
		iFetNum++;
	}
	m_bEnableQueryFlag = 1;
	return TRUE;
	*/
	
	int iNum = 0,iCcNum = 0;
	char buffer[CHAR_MAX_TASK_MSG_PACKAGES];
	LatLonMsg *pLonLatMsg = (LatLonMsg*)buffer;
	CCStatsResultMap::iterator itCCMap;
	char strCcName[64];
	while( StruFetchRule.TotalNums > iNum)
	{
		if( (FL_LAT == StruFetchRule.FieldID[iNum]) || (FL_LON == StruFetchRule.FieldID[iNum]))
		{
			itCCMap = StruHandleObjects.MapCC.begin();
			while( itCCMap != StruHandleObjects.MapCC.end() )
			{
				i = itCCMap->first.find_first_of(",");
				if (i != string::npos)
				{	
					memset(strCcName,0,64);
					memcpy(strCcName,itCCMap->first.c_str(),i);
					TRACE_LOG("[_Debug]: m_CcLonLatMap insert strCcName is:%s",strCcName);
					m_CcLonLatMap.insert(CC_LonLatMap::value_type(strCcName,pair<string,string>("","")));
					pLonLatMsg->Count++;//[_Debug]
					if(51 > pLonLatMsg->Count)//[_Debug]
						strcpy(pLonLatMsg->result[iCcNum++].CellCode,strCcName);//[_Debug]
					else
						pLonLatMsg->Count--;
				}
				itCCMap++;
			}
			pLonLatMsg->type = MSG_LON_LAN_QUERY;	
			pLonLatMsg->len = sizeof(LatLonMsg) - sizeof(TRawMsg) + iCcNum*sizeof(LonLatStruct);//[_Debug]
			pLonLatMsg->Count = iCcNum;//[_Debug]
			if(pRemoteAgent){TRACE_LOG("[_Debug]: CStatsSegmentThread send query LAT/LON msg !,Count=%u",pLonLatMsg->Count);
				pRemoteAgent->SendMsg(pLonLatMsg);
			}else
			{
				OSSleep(1500);TRACE_LOG("[_Debug]: CStatsSegmentThread core agent is not connect !");
				SendMsg(pLonLatMsg);
			}
			return FALSE;
		}
		iNum++;
	}
	m_bEnableQueryFlag = 1;
	TRACE_LOG("[_Debug]: CStatsDotThread TaskExecuteInit over !");
}


void CStatsSegmentThread::QueryCore()
{
	if(m_bEnableQueryFlag){
		if(pRemoteAgent){
			if(0 != m_CCnums){
				TRACE_LOG("[_Error]: CStatsSegmentThread m_CCnums=%llu, so last Handleing is not over !",m_CCnums);
				if(NULL != m_CoreReturn_pf){
				fflush(m_CoreReturn_pf);fclose(m_CoreReturn_pf);
				}
				m_CCnums = 0;
			}
			CWorkThread::QueryCore();
			m_CacheFileSet.clear();
		}
		else{
			TRawMsg QueryCoreMsg;
			INIT_MSG_HEADER(&QueryCoreMsg);
			QueryCoreMsg.type = MSG_QUERY_CORE_TIMER;
			OSSleep(1000);
			TRACE_LOG("[error]_: CStatsSegmentThread the Core agent is not connect !");
			SendMsg(&QueryCoreMsg);
		}	
	}
	else{
		TRACE_LOG("[warnning]: waiting get (LON,LAT) of CellCode!");
	}
}

BOOL CStatsSegmentThread::HandleResponseData( TCCQueryRSLTMsg2* msg )
{	
	CCStatsResultMap::iterator itMapCC;
	U64 iResultNum,iFieldNum;
	switch(iCoreQueryType)
	{
		case QueryCC_Phone:
		{
			TCCQueryRSLTMsg2 *pResponseMsg = (TCCQueryRSLTMsg2*)msg;			
			m_pUserState2 = pResponseMsg->states;
			iResultNum = msg->Count;
			if(NULL == m_CoreReturn_pf){
				memset(file_name,0,128);
				m_CoreReturn_pf = PrepairFile(pResponseMsg->InvokeID,file_name,NULL,1);
				if(NULL == m_CoreReturn_pf){
					TRACE_LOG("[_error]: PrepairFile return NULL !");
					return FALSE;
				}
			}
			if( Filter_Field&RuleID )//need handle filter rule
			{				
				while( 0 < iResultNum--)
				{
					if(!Filter(m_pUserState2))
					{
						m_pUserState2++;
						continue;
					}					
					fprintf(m_CoreReturn_pf,"%s;%llu;%u\n",pResponseMsg->CellCode,m_pUserState2->MDN,pResponseMsg->PosFlag);	
					m_pUserState2++;
				}				
			}
			else
			{
				while(0 < iResultNum--)
				{
					//TRACE_LOG("[_Debug]:%s; %llu;%u",pResponseMsg->CellCode,m_pUserState2->MDN,pResponseMsg->PosFlag);	
					fprintf(m_CoreReturn_pf,"%s;%llu;%u\n",pResponseMsg->CellCode,m_pUserState2->MDN,pResponseMsg->PosFlag);	
					m_pUserState2++;
				}
			}
			
			if( (1 == pResponseMsg->TailFlag) && (++m_CCnums == StruHandleObjects.MapCC.size()))
			{//TRACE_LOG("[_Debug]: fclose(m_CoreReturn_pf);");
				fflush(m_CoreReturn_pf);fclose(m_CoreReturn_pf);
				m_CacheFileSet.insert(set<string>::value_type(file_name));
				m_CoreReturn_pf = NULL;
			}
		}
		break;
		//Reserved interface
		/*case QueryIMSI_Status:			
		case QueryMDN_Status:
			TRTQueryMsg	*pQueryMsg = (TRTQueryMsg*)msg;
		break;*/
		default:
		break;
	}
	return TRUE;
}

BOOL CStatsSegmentThread::Filter(TUserState2* pstru)
{
	int i = 0;
	while( StruFilterRule.TotalNums > i)
	{
		switch(StruFilterRule.FieldID[i])
		{
			case FL_PowerState:
				if(pstru->PowerState != StruFilterRule.FilterVaule[i])
					return FALSE;
				break;
			case FL_BusyState:
				if(pstru->BusyState != StruFilterRule.FilterVaule[i])
					return FALSE;
				break;
			case FL_EventID:
				if(pstru->EventID != StruFilterRule.FilterVaule[i])
					return FALSE;
				break;
			default:
			break;
		}
		i++;
	}
	return TRUE;
}

BOOL CStatsSegmentThread::GetEarliestCacheFileName(char* pFileName)
{
	set<string>::iterator itCacheFileSet;
	itCacheFileSet = m_CacheFileSet.begin();//**********************排序问题待确认***********************(~_~)(*~_~*)
	if(itCacheFileSet != m_CacheFileSet.end())
	{
		sprintf(pFileName,"%s/%s",struTaskPackages.Filedirectory,itCacheFileSet->c_str());
		m_CacheFileSet.erase(itCacheFileSet);
		return TRUE;
	}
	return FALSE;
}

U32 CStatsSegmentThread::GetCacheFileNums()
{
	return m_CacheFileSet.size();
}

void CStatsSegmentThread::GetLonLatMap(CC_LonLatMap* pMap)
{
	pMap = &m_CcLonLatMap;
}



//只做记录存储
CRecordThread::CRecordThread()
{
	m_pAesResult = NULL;
	m_pRepResult = NULL;
}

CRecordThread::~CRecordThread()
{
	delete [] m_pRepResult;
	delete [] m_pAesResult;
}

BOOL CRecordThread::OnMsg(TRawMsg * msg,IMsg * remote_src)
{
	if( MSG_CLOSE_TASK == msg->type )
	{
		Close();
	}
	else if(MSG_HEART_BEAT_TIMER == msg->type)
	{
		HeartBeat();
	}
	else if(MSG_EXECUTE_TASK_INIT == msg->type)
	{
		if(TRUE == TaskExecuteInit())
		{
			QueryCore();
			AddTimer(&m_QueryCoreTimer);
		}
	}
	else if(MSG_QUERY_CORE_TIMER == msg->type)
	{
		QueryCore();
	}
	else if(MSG_TYPE_CCQUERYRSLT2_MSG == msg->type)
	{
		HandleResponseData((TCCQueryRSLTMsg2*)msg);
	}
	else if(MT_SESSION_CONNECT == msg->type)
	{
		TRACE_LOG("Session connected,    name = '%s'", ((TSessionConnect*)msg)->name);
		if( !strcmp(((TSessionConnect*)msg)->agent_name,AGENT_NAME_OIDD_CORE))
		{
			pRemoteAgent = ((TSessionConnect*)msg)->session;
		}
	}
	else if(MT_SESSION_DISCONNECT == msg->type)
	{
		TRACE_LOG("Session disconnected,    name = '%s'", ((TSessionConnect*)msg)->name);
		if( !strcmp(((TSessionConnect*)msg)->agent_name,AGENT_NAME_OIDD_CORE))
		{
			pRemoteAgent = NULL;
		}
	}
	else
	{
		TRACE_LOG("Session not Know,    name = '%s'", ((TSessionConnect*)msg)->name);
	}
	
	return TRUE;
}

void CRecordThread::QueryCore()
{
	if(pRemoteAgent){
		if(0 != m_iQueryNums){
			TRACE_LOG("[_Error]: CStatsSegmentThread m_iQueryNums=%llu, so last Handleing is not over !",m_iQueryNums);
			if(NULL != m_CoreReturn_pf){
				fflush(m_CoreReturn_pf);fclose(m_CoreReturn_pf);
			}
			m_iQueryNums = 0;
		}
		CWorkThread::QueryCore();
	}
	else{
		TRawMsg QueryCoreMsg;
		INIT_MSG_HEADER(&QueryCoreMsg);
		QueryCoreMsg.type = MSG_QUERY_CORE_TIMER;
		OSSleep(1000);
		TRACE_LOG("[error]_: CRecordThread the Core agent is not connect !");
		SendMsg(&QueryCoreMsg);
	}	
}

BOOL CRecordThread::TaskExecuteInit()
{
	char* pchar;
	CWorkThread::TaskExecuteInit();
	if( 0 < StruAesRule.TotalNums ){
		m_pAesResult = (Arrary_AesResult*)new char[StruAesRule.TotalNums*sizeof(Arrary_AesResult)*MAX_CCQUERYRSLT2_MSGS_BACK];
		memset(m_pAesResult,0,StruAesRule.TotalNums*sizeof(Arrary_AesResult)*MAX_CCQUERYRSLT2_MSGS_BACK);
	}
	if( 0 < StruReplaceRule.TotalNums ){
		m_pRepResult = (Arrary_RepResult*)new char[StruReplaceRule.TotalNums*sizeof(Arrary_RepResult)*MAX_CCQUERYRSLT2_MSGS_BACK];
		memset(m_pRepResult,0,StruReplaceRule.TotalNums*sizeof(Arrary_RepResult)*MAX_CCQUERYRSLT2_MSGS_BACK);
	}
	return TRUE;
}

void CRecordThread::HandleEncrypt(TCCQueryRSLTMsg2* msg)
{
	U32 i = 0,wResultNum = 0;
	char cObject[MAX_AES_RESULT_CHAR_NUMS];
	string strAesResult;
	memset(cObject,0,MAX_AES_RESULT_CHAR_NUMS);
	if(AES_Encrypt | RuleID){//TRACE_LOG("[_Debug]: StruAesRule.TotalNums:%u,msg->Count:%u,RuleID:%d,StruAesRule.FieldID[0]:%u,StruAesRule.FieldID[0]:%u",
		//StruAesRule.TotalNums,msg->Count,RuleID,StruAesRule.FieldID[0],StruAesRule.FieldID[1],StruAesRule.FieldID[2]);
		memset(m_pAesResult,0,StruAesRule.TotalNums*sizeof(Arrary_AesResult)*MAX_CCQUERYRSLT2_MSGS_BACK);
		while(StruAesRule.TotalNums > i){
			switch(StruAesRule.FieldID[i])
			{
				case FL_MDN:
					wResultNum = 0;
					while( msg->Count > wResultNum)
					{
						memset(cObject,0,MAX_AES_RESULT_CHAR_NUMS);
						sprintf(cObject,"%llu",msg->states[wResultNum].MDN);
						strAesResult = encrypt_Ex(cObject,1);
						//TRACE_LOG("[_Debug]: AES_encrypt result:%s",strAesResult.c_str());
						strcpy(m_pAesResult[wResultNum*StruAesRule.TotalNums+StruAesRule.ResPlace[FL_MDN]],strAesResult.c_str());
						wResultNum++;
					}
				break;
				case FL_IMSI:
					wResultNum = 0;
					while( msg->Count > wResultNum)
					{
						memset(cObject,0,MAX_AES_RESULT_CHAR_NUMS);
						sprintf(cObject,"%llu",msg->states[wResultNum].MDN);
						strAesResult = encrypt_Ex(cObject,1);
						strcpy(m_pAesResult[wResultNum*StruAesRule.TotalNums+StruAesRule.ResPlace[FL_IMSI]],strAesResult.c_str());
						wResultNum++;
					}
				break;
				case FL_CC:
					wResultNum = 0;
					while( msg->Count > wResultNum)
					{
						memset(cObject,0,MAX_AES_RESULT_CHAR_NUMS);
						sprintf(cObject,"%llu",msg->states[wResultNum].MDN);
						strAesResult = encrypt_Ex(cObject,1);
						strcpy(m_pAesResult[wResultNum*StruAesRule.TotalNums+StruAesRule.ResPlace[FL_CC]],strAesResult.c_str());
						wResultNum++;
					}
				break;
				default:
				break;
			}
			i++;
		}
	}
	i = 0;
	if(Replace_Encrypt | RuleID){//TRACE_LOG("[_Debug]:StruReplaceRule.TotalNums:%u,msg->Count:%u,RuleID:%d,StruAesRule.FieldID[0]:%u,StruAesRule.FieldID[0]:%u",
		//StruReplaceRule.TotalNums,msg->Count,RuleID,StruReplaceRule.FieldID[0],StruReplaceRule.FieldID[1],StruReplaceRule.FieldID[2]);
		int iRepAddr;
		memset(m_pRepResult,0,StruReplaceRule.TotalNums*sizeof(Arrary_RepResult)*MAX_CCQUERYRSLT2_MSGS_BACK);
		while(StruReplaceRule.TotalNums > i){
			switch(StruReplaceRule.FieldID[i])
			{
				case FL_MDN:
					wResultNum = 0;
					while(msg->Count > wResultNum)
					{
						memset(cObject,0,MAX_AES_RESULT_CHAR_NUMS);
						sprintf(cObject,"%llu",msg->states[wResultNum].MDN);
						iRepAddr = StruReplaceRule.StartAddr[i]-1;
						while(StruReplaceRule.EndAddr[i] != iRepAddr){
							cObject[iRepAddr++] = StruReplaceRule.To[i];
						}
						strcpy(m_pRepResult[wResultNum*StruReplaceRule.TotalNums+StruReplaceRule.ResPlace[FL_MDN]],cObject);
						//TRACE_LOG("[_Debug]: To[0]:%u,To[1]:%u,To[2]:%u,m_pRepResult[%u]:%s",StruReplaceRule.To[0],StruReplaceRule.To[1],StruReplaceRule.To[2],wResultNum*StruReplaceRule.TotalNums+StruReplaceRule.ResPlace[FL_MDN],m_pRepResult[wResultNum*StruReplaceRule.TotalNums+StruReplaceRule.ResPlace[FL_MDN]]);
						wResultNum++;
					}
				break;
				case FL_IMSI:
					wResultNum = 0;
					while(msg->Count > wResultNum)
					{
						memset(cObject,0,MAX_AES_RESULT_CHAR_NUMS);
						sprintf(cObject,"%llu",msg->states[wResultNum].IMSI);
						iRepAddr = StruReplaceRule.StartAddr[i]-1;
						while(StruReplaceRule.EndAddr[i] != iRepAddr){
							cObject[iRepAddr++] = StruReplaceRule.To[i];
						}
						strcpy(m_pRepResult[wResultNum*StruReplaceRule.TotalNums+StruReplaceRule.ResPlace[FL_IMSI]],cObject);
						wResultNum++;
					}
				break;
				case FL_CC:
					wResultNum = 0;
					while(msg->Count > wResultNum)
					{
						memset(cObject,0,MAX_AES_RESULT_CHAR_NUMS);
						sprintf(cObject,"%s",msg->CellCode);
						iRepAddr = StruReplaceRule.StartAddr[i]-1;
						while(StruReplaceRule.EndAddr[i] != iRepAddr){
							cObject[iRepAddr++] = StruReplaceRule.To[i];
						}													
						strcpy(m_pRepResult[wResultNum*StruReplaceRule.TotalNums+StruReplaceRule.ResPlace[FL_CC]],cObject);
						wResultNum++;
					}
				break;
				default:
				break;
			}
			i++;
		};
	}
}

BOOL CRecordThread::HandleResponseData( TCCQueryRSLTMsg2* msg )
{	
	char AesResult[128];
	switch(iCoreQueryType)
	{
		case QueryCC_Phone:
		{
			TCCQueryRSLTMsg2 *pResponseMsg = msg;
			TUserState2 *m_pUserState2 = pResponseMsg->states;
			U32 iResultNum = 0,iFetchNum;
			
			if(NULL == m_CoreReturn_pf){
				memset(file_name,0,128);
				m_CoreReturn_pf = PrepairFile(pResponseMsg->InvokeID,file_name);
				if(NULL == m_CoreReturn_pf){
					TRACE_LOG("[_error]: PrepairFile return NULL !");
					return FALSE;
				}
			}
			HandleEncrypt(msg);
			//TRACE_LOG("[_Debug]: HandleEncrypt(msg); over!");
			if( Filter_Field&RuleID )//need handle filter rule
			{				
				while( pResponseMsg->Count > iResultNum)
				{
					if(!Filter(m_pUserState2))
					{
						m_pUserState2++;
						continue;
					}
					if( Fetch_Field&RuleID ){	
						iFetchNum = 0;
						while(StruFetchRule.TotalNums > iFetchNum)
						{
							switch(StruFetchRule.FieldID[iFetchNum])
							{
								case FL_CC:
									if(TRUE == StruAesRule.IsAes[FL_CC])
										fprintf(m_CoreReturn_pf,"%s ",m_pAesResult[StruAesRule.TotalNums*iResultNum+StruAesRule.ResPlace[FL_CC]]);
									else if(TRUE == StruReplaceRule.IsRep[FL_CC])
										fprintf(m_CoreReturn_pf,"%s ",m_pRepResult[StruReplaceRule.TotalNums*iResultNum+StruReplaceRule.ResPlace[FL_CC]]);
									else
										fprintf(m_CoreReturn_pf,"%s ",pResponseMsg->CellCode);
								break;
								case FL_MDN:
									if(TRUE == StruAesRule.IsAes[FL_MDN])
										fprintf(m_CoreReturn_pf,"%s ",m_pAesResult[StruAesRule.TotalNums*iResultNum+StruAesRule.ResPlace[FL_MDN]]);
									else if(TRUE == StruReplaceRule.IsRep[FL_MDN])
										fprintf(m_CoreReturn_pf,"%s ",m_pRepResult[StruReplaceRule.TotalNums*iResultNum+StruReplaceRule.ResPlace[FL_MDN]]);
									else
										fprintf(m_CoreReturn_pf,"%llu ",m_pUserState2->MDN);	
								break;
								case FL_IMSI:
									if(TRUE == StruAesRule.IsAes[FL_IMSI])
										fprintf(m_CoreReturn_pf,"%s ",m_pAesResult[StruAesRule.TotalNums*iResultNum+StruAesRule.ResPlace[FL_IMSI]]);
									else if(TRUE == StruReplaceRule.IsRep[FL_IMSI])
										fprintf(m_CoreReturn_pf,"%s ",m_pRepResult[StruReplaceRule.TotalNums*iResultNum+StruReplaceRule.ResPlace[FL_IMSI]]);
									else
										fprintf(m_CoreReturn_pf,"%llu ",m_pUserState2->IMSI);	
								break;
								case FL_BusyState:
									fprintf(m_CoreReturn_pf,"%u ",m_pUserState2->BusyState);	
								break;
								case FL_PowerState:
									fprintf(m_CoreReturn_pf,"%u ",m_pUserState2->PowerState);
								break;
								case FL_PosFlag:
									fprintf(m_CoreReturn_pf,"%u ",pResponseMsg->PosFlag);
								break;	
								case FL_CurTime:
									fprintf(m_CoreReturn_pf,"%lld ",m_pUserState2->CurTime);
								break;
								case FL_EventID:
									fprintf(m_CoreReturn_pf,"%u ",m_pUserState2->EventID);	
								break;
								default:
								break;
							}
							iFetchNum++;
						}
						fprintf(m_CoreReturn_pf,"\n");
					}
					else{
						if(TRUE == StruAesRule.IsAes[FL_MDN]){//TRACE_LOG("[_Debug]: m_pAesResult[%d]:%s ",StruAesRule.TotalNums*iResultNum+StruAesRule.ResPlace[FL_MDN],m_pAesResult[StruAesRule.TotalNums*iResultNum+StruAesRule.ResPlace[FL_MDN]]);
							fprintf(m_CoreReturn_pf,"%s ",m_pAesResult[StruAesRule.TotalNums*iResultNum+StruAesRule.ResPlace[FL_MDN]]);
						}else if(TRUE == StruReplaceRule.IsRep[FL_MDN])
							fprintf(m_CoreReturn_pf,"%s ",m_pRepResult[StruReplaceRule.TotalNums*iResultNum+StruReplaceRule.ResPlace[FL_MDN]]);
						else
							fprintf(m_CoreReturn_pf,"%llu ",m_pUserState2->MDN);
						fprintf(m_CoreReturn_pf,"%lld ",m_pUserState2->CurTime);
						if(TRUE == StruAesRule.IsAes[FL_CC])
							fprintf(m_CoreReturn_pf,"%s ",m_pAesResult[StruAesRule.TotalNums*iResultNum+StruAesRule.ResPlace[FL_CC]]);
						else if(TRUE == StruReplaceRule.IsRep[FL_CC])
							fprintf(m_CoreReturn_pf,"%s ",m_pRepResult[StruReplaceRule.TotalNums*iResultNum+StruReplaceRule.ResPlace[FL_CC]]);
						else
							fprintf(m_CoreReturn_pf,"%s ",pResponseMsg->CellCode);
						fprintf(m_CoreReturn_pf,"%u\n",m_pUserState2->PowerState);
						//TRACE_LOG("[_Debug]: iResultNum:%u,%s,%u,%llu,%u,%u,%u\n",iResultNum,pResponseMsg->CellCode,pResponseMsg->PosFlag,m_pUserState2->MDN,
						//m_pUserState2->PowerState,m_pUserState2->BusyState,m_pUserState2->EventID);
					}
					m_pUserState2++;
					iResultNum++;
				}
				
			}
			else
			{
				while(pResponseMsg->Count > iResultNum)
				{
					if( Fetch_Field&RuleID ){	
						iFetchNum = 0;
						while(StruFetchRule.TotalNums > iFetchNum)
						{
							switch(StruFetchRule.FieldID[iFetchNum])
							{
								case FL_CC:
									if(TRUE == StruAesRule.IsAes[FL_CC])
										fprintf(m_CoreReturn_pf,"%s ",m_pAesResult[StruAesRule.TotalNums*iResultNum+StruAesRule.ResPlace[FL_CC]]);
									else if(TRUE == StruReplaceRule.IsRep[FL_CC])
										fprintf(m_CoreReturn_pf,"%s ",m_pRepResult[StruReplaceRule.TotalNums*iResultNum+StruReplaceRule.ResPlace[FL_CC]]);
									else
										fprintf(m_CoreReturn_pf,"%s ",pResponseMsg->CellCode);
								break;
								case FL_MDN:
									if(TRUE == StruAesRule.IsAes[FL_MDN])
										fprintf(m_CoreReturn_pf,"%s ",m_pAesResult[StruAesRule.TotalNums*iResultNum+StruAesRule.ResPlace[FL_MDN]]);
									else if(TRUE == StruReplaceRule.IsRep[FL_MDN])
										fprintf(m_CoreReturn_pf,"%s ",m_pRepResult[StruReplaceRule.TotalNums*iResultNum+StruReplaceRule.ResPlace[FL_MDN]]);
									else
										fprintf(m_CoreReturn_pf,"%llu ",m_pUserState2->MDN);	
								break;
								case FL_IMSI:
									if(TRUE == StruAesRule.IsAes[FL_IMSI])
										fprintf(m_CoreReturn_pf,"%s ",m_pAesResult[StruAesRule.TotalNums*iResultNum+StruAesRule.ResPlace[FL_IMSI]]);
									else if(TRUE == StruReplaceRule.IsRep[FL_IMSI])
										fprintf(m_CoreReturn_pf,"%s ",m_pRepResult[StruReplaceRule.TotalNums*iResultNum+StruReplaceRule.ResPlace[FL_IMSI]]);
									else
										fprintf(m_CoreReturn_pf,"%llu ",m_pUserState2->IMSI);	
								break;
								case FL_BusyState:
									fprintf(m_CoreReturn_pf,"%u ",m_pUserState2->BusyState);	
								break;
								case FL_PowerState:
									fprintf(m_CoreReturn_pf,"%u ",m_pUserState2->PowerState);
								break;
								case FL_PosFlag:
									fprintf(m_CoreReturn_pf,"%u ",pResponseMsg->PosFlag);
								break;	
								case FL_CurTime:
									fprintf(m_CoreReturn_pf,"%lld ",m_pUserState2->CurTime);
								break;
								case FL_EventID:
									fprintf(m_CoreReturn_pf,"%u ",m_pUserState2->EventID);	
								break;
								default:
								break;
							}
							iFetchNum++;
						}
						fprintf(m_CoreReturn_pf,"\n");
					}
					else{
						if(TRUE == StruAesRule.IsAes[FL_MDN])
							fprintf(m_CoreReturn_pf,"%s ",m_pAesResult[StruAesRule.TotalNums*iResultNum+StruAesRule.ResPlace[FL_MDN]]);
						else if(TRUE == StruReplaceRule.IsRep[FL_MDN])//TRACE_LOG("[_Debug]: m_pRepResult[%u]:%s",iResultNum*StruReplaceRule.TotalNums+StruReplaceRule.ResPlace[FL_MDN],m_pRepResult[iResultNum*StruReplaceRule.TotalNums+StruReplaceRule.ResPlace[FL_MDN]]);
							fprintf(m_CoreReturn_pf,"%s ",m_pRepResult[StruReplaceRule.TotalNums*iResultNum+StruReplaceRule.ResPlace[FL_MDN]]);
						else
							fprintf(m_CoreReturn_pf,"%llu ",m_pUserState2->MDN);
						fprintf(m_CoreReturn_pf,"%lld ",m_pUserState2->CurTime);
						if(TRUE == StruAesRule.IsAes[FL_CC])
							fprintf(m_CoreReturn_pf,"%s ",m_pAesResult[StruAesRule.TotalNums*iResultNum+StruAesRule.ResPlace[FL_CC]]);
						else if(TRUE == StruReplaceRule.IsRep[FL_CC])
							fprintf(m_CoreReturn_pf,"%s ",m_pRepResult[StruReplaceRule.TotalNums*iResultNum+StruReplaceRule.ResPlace[FL_CC]]);
						else
							fprintf(m_CoreReturn_pf,"%s ",pResponseMsg->CellCode);
						fprintf(m_CoreReturn_pf,"%u\n",m_pUserState2->PowerState);
					}
					m_pUserState2++;
					iResultNum++;
				}
			}			
			if(1 == pResponseMsg->TailFlag)
			{
				if(StruHandleObjects.MapCC.size() == ++m_iQueryNums){
					fflush(m_CoreReturn_pf);fclose(m_CoreReturn_pf);
					m_CoreReturn_pf = NULL;
				}
			}
		}
		break;
		//Reserved interface
		/*case QueryIMSI_Status:			
		case QueryMDN_Status:
			TRTQueryMsg	*pQueryMsg = (TRTQueryMsg*)msg;
		break;*/
		default:
		break;
	}
}

BOOL CRecordThread::Filter(TUserState2* pstru)
{
	int i = 0;
	while( StruFilterRule.TotalNums > i)
	{
		switch(StruFilterRule.FieldID[i])
		{
			case FL_PowerState:
				if(pstru->PowerState != StruFilterRule.FilterVaule[i])
					return FALSE;
				break;
			case FL_BusyState:
				if(pstru->BusyState != StruFilterRule.FilterVaule[i])
					return FALSE;
				break;
			case FL_EventID:
				if(pstru->EventID != StruFilterRule.FilterVaule[i])
					return FALSE;
				break;
			default:
			break;
		}
		i++;
	}
	return TRUE;
}


//手机号码触发业务
CPhoneTouchThread::CPhoneTouchThread()
{
	m_PhoneCCMap.clear();
}

CPhoneTouchThread::CPhoneTouchThread(IMsg * pRemote)
{
	m_pIn = pRemote;
}

CPhoneTouchThread::~CPhoneTouchThread()
{
	;
}

BOOL CPhoneTouchThread::OnMsg(TRawMsg * msg,IMsg * remote_src)
{
	if( MSG_CLOSE_TASK == msg->type )
	{
		Close();
	}
	else if(MSG_HEART_BEAT_TIMER == msg->type)
	{
		HeartBeat();
	}
	else if(MSG_EXECUTE_TASK_INIT == msg->type)
	{
		if(pRemoteAgent){
			TCoreAddMDNsMsg DelBeforeMsg;
			INIT_MSG_HEADER(&DelBeforeMsg);
			DelBeforeMsg.type = MSG_TYPE_OIDDCORE_ADDMDNS;
			DelBeforeMsg.ActionType = 3;
			DelBeforeMsg.Count = 0;
			pRemoteAgent->SendMsg(&DelBeforeMsg);
		}
		else{
			TRawMsg QueryCoreMsg;
			INIT_MSG_HEADER(&QueryCoreMsg);
			QueryCoreMsg.type = MSG_EXECUTE_TASK_INIT;
			OSSleep(1000);
			TRACE_LOG("[error]_: CPhoneTouchThread the Core agent is not connect !");
			SendMsg(&QueryCoreMsg);
			return FALSE;
		}	
		TaskExecuteInit();
		QueryCore();
	}
	else if(MSG_QUERY_CORE_TIMER == msg->type)
	{
		QueryCore();
	}
	else if(MSG_TYPE_OIDDCORE_NOTIFY == msg->type)
	{
		HandleResponseData((TCoreNotifyMsg*)msg);
	}
	else if(MT_SESSION_CONNECT == msg->type)
	{
		TRACE_LOG("Session connected,    name = '%s'", ((TSessionConnect*)msg)->name);
		if( !strcmp(((TSessionConnect*)msg)->agent_name,AGENT_NAME_OIDD_CORE))
		{
			pRemoteAgent = ((TSessionConnect*)msg)->session;
		}
	}
	else if(MT_SESSION_DISCONNECT == msg->type)
	{
		TRACE_LOG("Session disconnected,    name = '%s'", ((TSessionConnect*)msg)->name);
		if( !strcmp(((TSessionConnect*)msg)->agent_name,AGENT_NAME_OIDD_CORE))
		{
			pRemoteAgent = NULL;
		}
	}
	else
	{
		TRACE_LOG("Session not Know,    name = '%s'", ((TSessionConnect*)msg)->name);
	}
	
	return TRUE;
}

BOOL CPhoneTouchThread::TaskExecuteInit()
{
	strings Strs,StrsChild,StrsFilter;
	strings::iterator itStrs,itCC;
	vector<U64>::iterator itVecMDN;
	I32 iNum = 0;
	
	CWorkThread::TaskExecuteInit();
	m_MaxWriteNum = 0;
	/*
	divide_string(struTaskPackages.HandleObjects.c_str(),Strs,";");
	itCC = Strs.end();
	itStrs = Strs.begin();
	while(itStrs != Strs.end())
	{
		if(!strcmp(itStrs->c_str(),"C"))
		{
			itCC = ++itStrs;
			break;
		}
		itStrs++;
	}
	itVecMDN = StruHandleObjects.VectorMDN_IMSI.begin();
	while( itVecMDN != StruHandleObjects.VectorMDN_IMSI.end() )
	{
		if( (!strcmp(itStrs->c_str(),"_C")) || (itCC == Strs.end()))
		{
			TRACE_LOG("[Debug][error]_: The phone not get the Dest_CC !");
			return FALSE;
		}
		m_PhoneCCMap.insert(PhoneCellCodeMap::value_type(*itVecMDN,*itCC));
		itCC++;
		itVecMDN++;
	}	
	*/
	return TRUE;
}

BOOL CPhoneTouchThread::HandleResponseData( TCoreNotifyMsg* msg )
{
	vector<U64>::iterator itMDNsMap;
	CCStatsResultMap::iterator itCCsMap;
	itMDNsMap = find(StruHandleObjects.VectorMDN_IMSI.begin(),StruHandleObjects.VectorMDN_IMSI.end(),msg->MDN);
	itCCsMap = StruHandleObjects.MapCC.find(msg->CellCode);
	//TRACE_LOG("[_Debug]: CPhoneTouchThread: get the oidd back msg,MDN:%llu,CellCode:%s",msg->MDN,msg->CellCode);
	if( (itMDNsMap != StruHandleObjects.VectorMDN_IMSI.end()) && (itCCsMap != StruHandleObjects.MapCC.end()) ){		
		memset(file_name,0,128);
		if(NULL == m_CoreReturn_pf){
			m_CoreReturn_pf = PrepairFile(struTaskPackages.InvokeID,file_name);
			if(NULL == m_CoreReturn_pf ){
				TRACE_LOG("[error]_: the CPhoneTouchThread result file create failure !");
				return FALSE;
			}
		}
		fprintf(m_CoreReturn_pf,"%llu|%llu|%u|%u|%s\r\n",msg->MDN,msg->IMSI,msg->PowerState,msg->BusyState,msg->CellCode);
		if(m_MaxWriteNum++ > 1){
			fflush(m_CoreReturn_pf);fclose(m_CoreReturn_pf);
			m_CoreReturn_pf = NULL;
		}
		return TRUE;
	}
	else{
		return FALSE;
	}
}

void CPhoneTouchThread::QueryCore()
{
	if(pRemoteAgent){
		CWorkThread::QueryCore();
	}
	else{
		TRawMsg QueryCoreMsg;
		INIT_MSG_HEADER(&QueryCoreMsg);
		QueryCoreMsg.type = MSG_QUERY_CORE_TIMER;
		OSSleep(1000);
		TRACE_LOG("[error]_: CPhoneTouchThread the Core agent is not connect !");
		SendMsg(&QueryCoreMsg);
	}	
}




CStatsCollectThread::CStatsCollectThread()
{
	;
}

CStatsCollectThread::~CStatsCollectThread()
{
	;
}

BOOL CStatsCollectThread::Prepare(long * pnResult)
{
	SetLoopInterval(1);
	m_wTimeNums = 1000;
	m_wLoopTime = 0;
	m_LiveFlag = 1;
	return TRUE;
}

void CStatsCollectThread::SetLoopTimeSec(U32 wTime)
{
	m_wTimeNums = wTime*1000;
}

void CStatsCollectThread::Close()
{
	m_LiveFlag = 0;
	while(m_HandleOver)
		usleep(100);
	OSSleep(10);
}

BOOL CStatsCollectThread::DoLoop(U32 nLoopCount, long * pnResult)
{
	U32 wCacheFileNums,wCacheFileNums1;
	char cFullPathName[128],cLineArray[128];
	strings strsContent;
	strings::iterator itstrs;
	set<string> Mdn_ImsiMap;
	FILE *fp = NULL;
	MapCCiterator itMapcc;
	
//	pair<set<string>::iterator::iterator,bool> IsInsertPair;
	
	Mdn_ImsiMap.clear();

	if( !m_LiveFlag ){
		return FALSE;
	}
	if(m_wTimeNums > m_wLoopTime++){
		return TRUE;
	}
	m_wLoopTime = 0;
	m_HandleOver = 1;
	wCacheFileNums = m_pSegStatsThread->GetCacheFileNums();	
	wCacheFileNums1 = wCacheFileNums;
	//TRACE_LOG("[_Debug]: CStatsCollectThread working,CacheFile has %u !",wCacheFileNums);
	Mdn_ImsiMap.clear();
	while( 0 < wCacheFileNums-- )
	{
		memset(cFullPathName,0,128);
		memset(cLineArray,0,128);
		m_pSegStatsThread->GetEarliestCacheFileName(cFullPathName);
		fp = fopen(cFullPathName,"a+");
		if(NULL == fp)
		{
			TRACE_LOG("[_Error]: CStatsCollectThread working,CacheFile %s open fail !",cFullPathName);
			goto HANDLEOVER;
		}
		while(NULL != fgets(cLineArray, 128, fp) )
		{
			divide_string(cLineArray,strsContent,";");
			itstrs = strsContent.begin();
			if(itstrs != strsContent.end()){
				if( TRUE == m_pSegStatsThread->IsExistInCCMap(itstrs->c_str(),itMapcc) ){
					itstrs++;
					if( (11 != itstrs->size()) && (13 != itstrs->size())){
						continue;
					}
					if(Mdn_ImsiMap.insert(*itstrs).second){
						itstrs++;//TRACE_LOG("[_Debug]: itMapcc->first:%s   !",itMapcc->first.c_str());
						if(strcmp(itstrs->c_str(),"0")){
							itMapcc->second.first += 1;
						}
						else{
							itMapcc->second.second += 1;
						}
					}else
					{
						TRACE_LOG("[_Debug]: Mdn_ImsiMap.insert(*itstrs).second----false, itMapcc->first:%s   !",itMapcc->first.c_str());
					}
				}
			}			
			memset(cLineArray,0,128);
		}
		fflush(fp);fclose(fp);
HANDLEOVER:
		fp = NULL;
		//remove the file
		char cmd[256];
		memset(cmd,0,256);
		sprintf(cmd,"/bin/rm -f %s",cFullPathName);
		//TRACE_LOG("[_Debug]: cmd:%s",cmd);
		//OSExecCmd(cmd);
		system(cmd);
		OSSleep(100);/**/
	}
	wCacheFileNums = m_pSegStatsThread->GetCacheFileNums();	
	if(0 < wCacheFileNums1){
		HandleStatsResult();	
		m_pSegStatsThread->ClearStatsResult();
	}
	m_HandleOver = 0;
	return TRUE;
}
void CStatsCollectThread::HandleStatsResult()
{
	FILE *pf = NULL;
	CCStatsResultMap BSMap;
	strings strsBS;
	CCStatsResultMap::iterator itBSMap;
	CCStatsResultMap::iterator itMapCC;
	CC_LonLatMap::iterator itLonLat;
	int	GradeAllFlag = 0;	
	U64 StatsNum,StatsNum1;
	int iResultNum;
	U64 iColNums;
	
	I32 iRuleID;
	I32 iQueryType;
	StruQueryObjects 	*pQueryObject;
	TaskExecutePackages *pTaskPackages;
	CC_LonLatMap		*pCCLonLatMap;
	StruFetch 			*pFetchRule;
	
	//iRuleID = m_pSegStatsThread->GetRuleID();
	//iQueryType = m_pSegStatsThread->GetQueryType();
	//m_pSegStatsThread->GetStruFetchRule(pFetchRule);
	//m_pSegStatsThread->GetLonLatMap(pCCLonLatMap);
	//m_pSegStatsThread->GetstruTaskPackage(pTaskPackages);
	//m_pSegStatsThread->GetStruQueryObject(pQueryObject);
	iRuleID = m_pSegStatsThread->RuleID;
	iQueryType = m_pSegStatsThread->iCoreQueryType;
	pFetchRule = &(m_pSegStatsThread->StruFetchRule);
	pCCLonLatMap = &(m_pSegStatsThread->m_CcLonLatMap);
	pTaskPackages = &(m_pSegStatsThread->struTaskPackages);
	pQueryObject = &(m_pSegStatsThread->StruHandleObjects);
	//TRACE_LOG("[_Debug]: m_pSegStatsThread address:%d, pTaskPackages:%d,m_pSegStatsThread->struTaskPackages:%d",m_pSegStatsThread,pTaskPackages,&(m_pSegStatsThread->struTaskPackages));
	switch(iQueryType)
	{
		case QueryCC_Phone:
		{
			if(NULL == pf){
				memset(m_FileName,0,128);
				//TRACE_LOG("[_Debug]: pTaskPackages->InvokeID:%d,",pTaskPackages->InvokeID);
				pf = m_pSegStatsThread->PrepairFile(pTaskPackages->InvokeID,m_FileName);
				if(NULL == pf){
					TRACE_LOG("[_Error]: PrepairFile return NULL !");
					return;
				}
			}	
			
			if( StatsAllNum == pTaskPackages->Resulttype ){
				switch(pTaskPackages->Grade)
				{
					case Grade_All:
						GradeAllFlag = 1;
					case Grade_Area:
						StatsNum = 0;
						itMapCC = pQueryObject->MapCC.begin();
						while(itMapCC !=  pQueryObject->MapCC.end())
						{
							StatsNum += itMapCC->second.first;
							StatsNum += itMapCC->second.second;
							itMapCC++;
						}
						fprintf(pf,"%llu %llu\n",pTaskPackages->InvokeID,StatsNum);
						if(!GradeAllFlag){
							break;
						}
					case Grade_BasicStation:
					{						
						StatsNum = 0;
						BSMap.clear();
						itMapCC = pQueryObject->MapCC.begin();
						while(itMapCC != pQueryObject->MapCC.end())
						{
							divide_string(itMapCC->first.c_str(),strsBS,",");
							itBSMap = BSMap.find(strsBS.at(0).c_str());
							if(itBSMap != BSMap.end()){
								itBSMap->second.first += itMapCC->second.first;
								itBSMap->second.second += itMapCC->second.second;
							}else{
								BSMap.insert(CCStatsResultMap::value_type(strsBS.at(0).c_str(),pair<U64,U64>(itMapCC->second.first,itMapCC->second.second)));
							}
							itMapCC++;	
						}
						itBSMap = BSMap.begin();
						if( Fetch_Field&iRuleID ){
							while(itBSMap !=  BSMap.end())
							{	
								iColNums = 0;
								fprintf(pf,"%s ",itBSMap->first.c_str());
								while( pFetchRule->TotalNums > iColNums)
								{
									switch(pFetchRule->FieldID[iColNums])
									{
										case FL_LON:
											itLonLat = pCCLonLatMap->find(itBSMap->first.c_str());
											if(itLonLat != pCCLonLatMap->end())
												fprintf(pf,"%s ",itLonLat->second.first.c_str());
											else
												fprintf(pf,"%s ","NoFind");
											break;
										case FL_LAT:
											itLonLat = pCCLonLatMap->find(itBSMap->first.c_str());
											if(itLonLat != pCCLonLatMap->end())
												fprintf(pf,"%s ",itLonLat->second.second.c_str());
											else
												fprintf(pf,"%s ","NoFind");
											break;
										default:
											break;
									}
									iColNums++;
								}
								fprintf(pf,"%llu\n",itBSMap->second.first+itBSMap->second.second);
								itBSMap++;	
							}
						}
						else{
							while(itBSMap !=  BSMap.end())
							{
								fprintf(pf,"%s %llu\n",itBSMap->first.c_str(),itBSMap->second.first+itBSMap->second.second);
								itBSMap++;
							}									
						}
					}
						if(!GradeAllFlag){
							break;
						}
					case Grade_Section://不支持，索取经纬度字段 **************************************(~_~)(*~_~*)
						itMapCC = pQueryObject->MapCC.begin();
						while(itMapCC !=  pQueryObject->MapCC.end())
						{
							fprintf(pf,"%s %llu\n",itMapCC->first.c_str(),itMapCC->second.first+itMapCC->second.second);
							itMapCC++;
						}
						if(!GradeAllFlag){
							break;
						}
					default:
					break;
				}
			}
			else if( StatsUnfoldNum == pTaskPackages->Resulttype )
			{
				switch(pTaskPackages->Grade)
				{
					case Grade_All:
						GradeAllFlag = 1;
					case Grade_Area:
						StatsNum = 0;
						StatsNum1 = 0;
						itMapCC = pQueryObject->MapCC.begin();
						while(itMapCC !=  pQueryObject->MapCC.end())
						{
							StatsNum += itMapCC->second.first;
							StatsNum1 += itMapCC->second.second;
							itMapCC++;
						}							
						fprintf(pf,"%llu %llu %llu\n",pTaskPackages->InvokeID,StatsNum,StatsNum1);
						if(!GradeAllFlag){
							break;
						}
					case Grade_BasicStation:
					{						
						StatsNum = 0;
						BSMap.clear();
						itMapCC = pQueryObject->MapCC.begin();
						while(itMapCC != pQueryObject->MapCC.end())
						{
							divide_string(itMapCC->first.c_str(),strsBS,",");
							itBSMap = BSMap.find(strsBS.at(0).c_str());
							if(itBSMap != BSMap.end()){
								itBSMap->second.first += itMapCC->second.first;
								itBSMap->second.second += itMapCC->second.second;
							}else{
								BSMap.insert(CCStatsResultMap::value_type(strsBS.at(0).c_str(),pair<U64,U64>(itMapCC->second.first,itMapCC->second.second)));
							}
							itMapCC++;	
						}
						itBSMap = BSMap.begin();
						if( Fetch_Field&iRuleID ){
							while(itBSMap !=  BSMap.end())
							{	
								fprintf(pf,"%s ",itBSMap->first.c_str());
								iColNums = 0;
								while( pFetchRule->TotalNums > iColNums)
								{
									switch(pFetchRule->FieldID[iColNums])
									{
										case FL_LON:
											itLonLat = pCCLonLatMap->find(itBSMap->first.c_str());
											if(itLonLat != pCCLonLatMap->end())
												fprintf(pf,"%s ",itLonLat->second.first.c_str());
											else
												fprintf(pf,"%s ","NoFind");
											break;
										case FL_LAT:
											itLonLat = pCCLonLatMap->find(itBSMap->first.c_str());
											if(itLonLat != pCCLonLatMap->end())
												fprintf(pf,"%s ",itLonLat->second.second.c_str());
											else
												fprintf(pf,"%s ","NoFind");
											break;
										default:
											break;
									}
									iColNums++;
								}
								fprintf(pf,"%llu %llu\n",itBSMap->second.first,itBSMap->second.second);
								itBSMap++;	
							}
						}
						else{
							while(itBSMap !=  BSMap.end())
							{//TRACE_LOG("[_Debug]: %s %llu %llu\n",itBSMap->first.c_str(),itBSMap->second.first,itBSMap->second.second);
								fprintf(pf,"%s %llu %llu\n",itBSMap->first.c_str(),itBSMap->second.first,itBSMap->second.second);
								itBSMap++;
							}									
						}
					}
						if(!GradeAllFlag){
							break;
						}
					case Grade_Section://不支持，索取经纬度字段 **************************************(~_~)(*~_~*)
						itMapCC = pQueryObject->MapCC.begin();
						while(itMapCC !=  pQueryObject->MapCC.end())
						{//TRACE_LOG("[_Debug]: %s %llu %llu\n",itMapCC->first.c_str(),itMapCC->second.first,itMapCC->second.second);
							fprintf(pf,"%s %llu %llu\n",itMapCC->first.c_str(),itMapCC->second.first,itMapCC->second.second);
							itMapCC++;
						}
						if(!GradeAllFlag){
							break;
						}
					default:
					break;
				}
			}
			fflush(pf);fclose(pf);
			pf = NULL;
		}
		break;
		//Reserved interface
		/*case QueryIMSI_Status:			
		case QueryMDN_Status:
			TRTQueryMsg	*pQueryMsg = (TRTQueryMsg*)msg;
		break;*/
		default:
		break;
	}
}

