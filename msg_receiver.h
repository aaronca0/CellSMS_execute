#ifndef __MSG_RECEIVER_H__
#define __MSG_RECEIVER_H__

#include <framework.h>
#include "workthread.h"
#include "msg_areasms_task_def.h"

#define CreateWorkThread(pclass,ClassName) 					\
	pclass = new ClassName();


class CMsgReceiver : public CMsgThread
{
public:
	CMsgReceiver();
	~CMsgReceiver();

	TUTime stru_Tutime;
	TRawMsg MsgTimer;
	CMsgThreadTimer m_CheckTimer;
private:

	map<U64,CWorkThread*>::iterator m_itTasklistMap;
	
	TaskStatusMsg m_StatusMsg;

	IMsg * pTaskDisptachAgent;
	IMsg * pBlacklistAgent;

	virtual BOOL Prepare(long *pnResult);
	virtual BOOL OnMsg(TRawMsg *msg, IMsg *remote_src);
	
	void StatusMsgInit(U64 TaskID, U8 TaskStatus);
	BOOL TaskPackagesHandle(TaskPackageMsg *msg,IMsg *pRemote);
	void SendWorkThreadStatus();
	
};






































#endif//__MSG_RECEIVER_H__
