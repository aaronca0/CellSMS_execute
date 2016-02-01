#include "msg_receiver.h"
#include "taskexecute_app.h"

extern map<U64,CWorkThread*> g_TaskWorkThreadMap;
extern set<CWorkThread*> g_RecycleSet;
extern CThreadLock g_WorkThreadMapLock;
extern U32 g_CheckInterval;



CMsgReceiver::CMsgReceiver()
{
	INIT_MSG_HEADER(&MsgTimer);
	MsgTimer.type = MSG_CHECK_TIMER;
	m_CheckTimer.SetMessage(&MsgTimer);
}

CMsgReceiver::~CMsgReceiver()
{
	;
}

BOOL CMsgReceiver::Prepare(long *pnResult)
{	
	m_CheckTimer.SetTime(g_CheckInterval*1000,TRUE);
	AddTimer(&m_CheckTimer);
	return TRUE;
}


BOOL CMsgReceiver::OnMsg(TRawMsg *msg, IMsg *remote_src)
{
	if( MSG_TYPE_TASK_ADD_DEL == msg->type )//new task packages message
	{
		TRACE_LOG("[_Debug]: get the ADD_DEL_Task_Msg !");
		TaskPackagesHandle((TaskPackageMsg*)msg,remote_src);
	}
	else if( MSG_TYPE_RESPONSE_BLACKLIST == msg->type )//get blacklist table message
	{
		if( NULL != pBlacklistAgent )
		{
			pBlacklistAgent->SendMsg(msg);
		}
	}
	else if( MSG_TYPE_REQUEST_BLACKLIST == msg->type )//query blacklist 
	{
		if( NULL != pTaskDisptachAgent )
		{
			pTaskDisptachAgent->SendMsg(msg);
		}
	}
	else if( MSG_TYPE_CHECK_TASK_STATUS == msg->type )//check the taskid open or not
	{/*
		if( g_TaskWorkThreadMap.end() == g_TaskWorkThreadMap.find(((TaskStatusMsg*)msg)->InvokeID) )
		{
			((TaskStatusMsg*)msg)->WorkStatus = 0;
		}else
		{
			((TaskStatusMsg*)msg)->WorkStatus = 1;
		}
		pTaskDisptachAgent->SendMsg(msg);
		*/
		TRACE_LOG("[_Debug]: receive check task status");
		((TaskStatusMsg*)msg)->WorkStatus = 0;
		pTaskDisptachAgent->SendMsg(msg);
		TRACE_LOG("[_Debug]: return check task status");
	}
	else if(MSG_CHECK_TIMER == msg->type)
	{
		SendWorkThreadStatus();
	}
	else if( MT_SESSION_CONNECT == msg->type )
	{
		TRACE_LOG("Session connected,    name = '%s'", ((TSessionConnect*)msg)->name);
		if( !strcmp(((TSessionConnect*)msg)->agent_name,AGENT_NAME_TASK_DISPATCH))
		{
			pTaskDisptachAgent = ((TSessionConnect*)msg)->session;
		}
		if( !strcmp(((TSessionConnect*)msg)->agent_name,AGENT_NAME_OIDD_CORE))
		{
			pBlacklistAgent = ((TSessionConnect*)msg)->session;
		}
	}
	else if( MT_SESSION_DISCONNECT == msg->type )
	{
		TRACE_LOG("Session disconnected,    name = '%s'", ((TSessionConnect*)msg)->name);
		if( !strcmp(((TSessionConnect*)msg)->agent_name,AGENT_NAME_TASK_DISPATCH))
		{
			pTaskDisptachAgent = NULL;
		}
		if( !strcmp(((TSessionConnect*)msg)->agent_name,AGENT_NAME_OIDD_CORE))
		{
			pBlacklistAgent = NULL;
		}
	}
	else
	{
		TRACE_LOG("Session not Know,    name = '%s'", ((TSessionConnect*)msg)->name);
	}
	return TRUE;
}


BOOL CMsgReceiver::TaskPackagesHandle(TaskPackageMsg *msg,IMsg *pRemote)
{
	//0.judge the way of task work,create or close
	if( 0 == msg->ExeFlag )//close task
	{
		TRawMsg CloseTaskMsg;
		INIT_MSG_HEADER(&CloseTaskMsg);
		CloseTaskMsg.type = MSG_CLOSE_TASK;
		m_itTasklistMap = g_TaskWorkThreadMap.find(msg->InvokeID);	
		if(m_itTasklistMap != g_TaskWorkThreadMap.end())
		{
			m_itTasklistMap->second->SendMsg(&CloseTaskMsg);
			g_RecycleSet.insert(m_itTasklistMap->second);
			g_TaskWorkThreadMap.erase(m_itTasklistMap);
			TRACE_LOG("[_Debug]: find the workthread,send CLOSE_TASK_MSG to them!");
		}

		StatusMsgInit(msg->InvokeID,0);
		if( NULL != pTaskDisptachAgent )
		{
			pTaskDisptachAgent->SendMsg(&m_StatusMsg);
		}
	}
	if( 1 == msg->ExeFlag )//create task
	{		
		CWorkThread* pCWorkThread = NULL;	
		//1.judge task type and create the type workthread
		m_itTasklistMap = g_TaskWorkThreadMap.find(msg->InvokeID);
		TRACE_LOG("[_Debug]: before create workthread !");
		if( g_TaskWorkThreadMap.end() == m_itTasklistMap )
		{ 		
			if( 1 == msg->Isphone )
			{
				pCWorkThread = new CPhoneTouchThread(pRemote);TRACE_LOG("[_Debug]: new a CPhoneTouchThread !");
			}else
			{
				switch(msg->Resulttype)
				{
					case StatsUnfoldNum:
					case StatsAllNum:
						switch(msg->Gathertype)
						{
							case TimeDot:
								pCWorkThread = new CStatsDotThread();TRACE_LOG("[_Debug]: new a CStatsDotThread !");
							break;
							case TimeSegment:
								pCWorkThread = new CStatsSegmentThread();TRACE_LOG("[_Debug]: new a CStatsSegmentThread !");
							break;
						}
					break;
					case Record:
						switch(msg->Gathertype)
						{
							case TimeDot:
							case TimeSegment:
							default:
								pCWorkThread = new CRecordThread();TRACE_LOG("[_Debug]: new a CRecordThread !");
							break;
						}
					break;
				}
			}
			if(!pCWorkThread){
				TRACE_LOG("[error]_: TaskID(%llu) Not find the type of WorkThread,and not create WorkThread!",msg->InvokeID);
				return FALSE;
			}
			g_TaskWorkThreadMap.insert(map<U64,CWorkThread*>::value_type(msg->InvokeID,pCWorkThread));
			m_itTasklistMap = g_TaskWorkThreadMap.find(msg->InvokeID);
			if( g_TaskWorkThreadMap.end() == m_itTasklistMap )
			{
				TRACE_LOG("[error]_: the TaskID(%llu) is working now,the Web not send close command and demand start second!",msg->InvokeID);
				return FALSE;
			}
			TRACE_LOG("[_Debug]: has created workthread ,Workthread Total numbers:%d ! ",g_TaskWorkThreadMap.size());
			//2.get the task data
			if( 0 == msg->PackageOverFlag)
			{
				m_itTasklistMap->second->SetHandleObjects(msg->OperateObjects);
				return TRUE;
			}
			TRACE_LOG("[_Debug]: before start workthread !");
			m_itTasklistMap->second->SetExeFlag(msg->ExeFlag);
			m_itTasklistMap->second->SetPackageOverFlag(msg->PackageOverFlag);
			m_itTasklistMap->second->SetInvokeID(msg->InvokeID);
			m_itTasklistMap->second->SetWorkstarttime(msg->Workstarttime);
			m_itTasklistMap->second->SetWorkstoptime(msg->Workstoptime);
			m_itTasklistMap->second->SetTaskendtime(msg->Taskendtime);
			m_itTasklistMap->second->SetIsphone(msg->Isphone);
			m_itTasklistMap->second->SetResulttype(msg->Resulttype);
			m_itTasklistMap->second->SetGrade(msg->Grade);
			m_itTasklistMap->second->SetGathertype(msg->Gathertype);
			m_itTasklistMap->second->SetFilefrequence(msg->Filefrequence);
			m_itTasklistMap->second->SetFiledirectory(msg->Filedirectory);
			m_itTasklistMap->second->SetTaskRule(&(msg->TaskRule));
			TRACE_LOG("[_Debug]: msg->len=%d,msg->OperateObjects.strlen=%d",msg->len,strlen(msg->OperateObjects));
			printf("[_Debug]: msg->OperateObjects:%s\n",msg->OperateObjects);
			m_itTasklistMap->second->SetHandleObjects(msg->OperateObjects);
			//3.the task start working
			
			pCWorkThread->Start();	
			TRACE_LOG("[_Debug]: after start workthread !");	
		}	
		else{
			TRACE_LOG("[_Debug]: the TaskID(%llu) had create workthread and working !",msg->InvokeID);
		}
	}
	return TRUE;
}

void CMsgReceiver::StatusMsgInit(U64 TaskID, U8 TaskStatus)
{
	memset(&m_StatusMsg,0,sizeof(TaskStatusMsg));
	INIT_MSG_HEADER(&m_StatusMsg);
	m_StatusMsg.InvokeID = TaskID;
	m_StatusMsg.WorkStatus = TaskStatus;//status close 		
	m_StatusMsg.type = MSG_TYPE_TASK_STATUS;
	
	TUGetTime(stru_Tutime);
	sprintf(m_StatusMsg.InsertTime,"%d-%d-%d %d:%d:%d",stru_Tutime.year,stru_Tutime.month,stru_Tutime.day,
		stru_Tutime.hour,stru_Tutime.minute,stru_Tutime.second);
}
void CMsgReceiver::SendWorkThreadStatus()
{
	m_itTasklistMap = g_TaskWorkThreadMap.begin();
	set<CWorkThread*>::iterator itRecycleSet = g_RecycleSet.begin();
	CWorkThread* pworkthread;
	//TRACE_LOG("[_Debug]: CMsgReceiver execute WorkThreadStatus()");
	while( m_itTasklistMap != g_TaskWorkThreadMap.end() )
	{
		if(TRUE == m_itTasklistMap->second->IsLive())
			StatusMsgInit(m_itTasklistMap->first,1);
		else{
			StatusMsgInit(m_itTasklistMap->first,0);
			//TRACE_LOG("[_Debug]: the workthread(%llu) is stop working !",m_itTasklistMap->first);
		}
		if( NULL != pTaskDisptachAgent )
		{
			pTaskDisptachAgent->SendMsg(&m_StatusMsg);
		}
		m_itTasklistMap++;
	}
	while(itRecycleSet != g_RecycleSet.end())
	{
		if( TRUE == (*itRecycleSet)->IsClose() ){
			TRACE_LOG("[_Debug]: the workthread is recycle memory !");
			pworkthread = *itRecycleSet;
			delete pworkthread;
			g_RecycleSet.erase(itRecycleSet);
		}
		itRecycleSet++;
	}
}

















