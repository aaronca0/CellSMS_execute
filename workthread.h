#ifndef _WORKTHREAD_H_
#define _WORKTHREAD_H_

#include <dirent.h>
#include <sys/types.h>

#include <framework.h>
#include "msg_areasms_task_def.h"
#include "QueryMsgDef.h"
//#include "seg_stats_thread.h"
#include "Rule_Handle_Packages.h"



class CWorkThread : public CMsgThread
{
public:
	CWorkThread();
	~CWorkThread();
	TUTime CurTime;	
	BOOL IsLive();
	
	void ClearStatsResult();
	BOOL IsExistInCCMap(const char * pchar,MapCCiterator &itMap);
	void GetstruTaskPackage(TaskExecutePackages* pTaskPackage);
	void GetStruQueryObject(StruQueryObjects* pStru);
	I32 GetQueryType();
	I32 GetRuleID();
	void GetStruFetchRule(StruFetch* pStru);
	
protected:

	friend class CMsgReceiver;

	IMsg* 	pRemoteAgent;
	I32 	iHeartValue;
	I32		iTaskType;//
	I32		iCoreQueryType;//
	U8		RuleID;//0:无规则 0bit:AES加密 1-需要AES加密 1bit:替换加密 1-需要替换加密  2bit:是否索取 1-需要        3bit:是否过滤 1-需要

	StruEncryptAES		StruAesRule;
	StruEncryptReplace	StruReplaceRule;
	StruFetch			StruFetchRule;
	StruFilter			StruFilterRule;
	
	TUTime 	DestTime;

	FILE * 	m_CoreReturn_pf;
	CRemoteMsgThreadTCPClient* pRemoteMsgThreadTCPClient;
	char 	file_name[128];
	
	TRawMsg TRawMsgTimer;
	CMsgThreadTimer m_CheckTimer;
	CMsgThreadTimer m_QueryCoreTimer;
	StruQueryObjects StruHandleObjects;
	TaskExecutePackages struTaskPackages;

	BOOL bCloseFlag;
	
	void SetExeFlag(I32 value){struTaskPackages.ExeFlag = value;};
	void SetPackageOverFlag(I32 value){struTaskPackages.PackageOverFlag = value;};
	void SetInvokeID(U64 value){struTaskPackages.InvokeID = value;};
	void SetWorkstarttime(I32 value){struTaskPackages.Workstarttime = value;};
	void SetWorkstoptime(I32 value){struTaskPackages.Workstoptime = value;};
	void SetTaskendtime(U64 value){struTaskPackages.Taskendtime = value;};
	void SetIsphone(I32 value){struTaskPackages.Isphone = value;};
	void SetGathertype(I32 value){struTaskPackages.Gathertype = value;};
	void SetResulttype(I32 value){struTaskPackages.Resulttype = value;};
	void SetGrade(I32 value){struTaskPackages.Grade = value;};
	void SetFilefrequence(I32 value){struTaskPackages.Filefrequence = value;};
	void SetFiledirectory(I8 *value){strcpy(struTaskPackages.Filedirectory,value);};
	void SetTaskRule(StruTaskRule* value){memcpy(&(struTaskPackages.TaskRule),value,sizeof(StruTaskRule));};
	void SetHandleObjects(char *value){struTaskPackages.HandleObjects.append(value);};
	
	
	virtual BOOL Prepare(long *pnResult);
	virtual BOOL TaskExecuteInit();
	virtual void QueryCore()=0;	
	virtual BOOL Cleanup(long *pnResult);
	virtual BOOL Close();
	virtual BOOL IsClose();

	virtual void EncryptAES(StruEncryptAES &StruAES){;};
	virtual void EncryptRep(StruEncryptReplace &StruRep){;};
	
	U8 GetFieldID(strings &strs_object,UserDefineRule* RuleStore,U8 RuleType);
	U8	MatchString(const char* str);
	
	BOOL TaskRuleAnalysis();
	FILE* PrepairFile(U64 invokeid,char* pFileName,char* pFolderName = NULL,U8 IsCacheFile = FALSE);
	BOOL CheckTime();
	void HeartBeat(){iHeartValue = 1;};
	
};

typedef map<string,pair<string,string> > CC_LonLatMap;
class CStatsDotThread : public CWorkThread
{
public:
	CStatsDotThread();
	~CStatsDotThread();

private:	
	
	TUserState2*	m_pUserState2;
	BOOL			m_bEnableQueryFlag;
	CC_LonLatMap 	m_CcLonLatMap;
	U32 			m_CCnums;
	
	virtual BOOL OnMsg(TRawMsg * msg,IMsg * remote_src);
	BOOL TaskExecuteInit();
	void QueryCore();
	BOOL HandleResponseData( TRawMsg* msg );
	BOOL Filter(TUserState2* pstru);
};


class CStatsSegmentThread;

class CStatsCollectThread : public CLoopThread
{
public:
	CStatsCollectThread();
	~CStatsCollectThread();

	void SetLoopTimeSec(U32 wTime);
	void Close();
	void SetSegStatsThread(CStatsSegmentThread* pCStatsSegThread){
		m_pSegStatsThread = pCStatsSegThread;};
	
protected:
	
	U32 m_wLoopTime;
	U32	m_wTimeNums;

	BOOL m_LiveFlag;
	BOOL m_HandleOver;
	char m_FileName[128];
	
	
	CStatsSegmentThread* m_pSegStatsThread;
	
	BOOL Prepare(long * pnResult);	
	virtual BOOL DoLoop(U32 nLoopCount, long * pnResult);
	void HandleStatsResult();
};

class CStatsSegmentThread : public CWorkThread
{
public:
	CStatsSegmentThread();
	~CStatsSegmentThread();
	
	CStatsCollectThread m_CollectThread;
	
protected:
	friend class CStatsCollectThread;

	U32 GetCacheFileNums();
	void GetLonLatMap(CC_LonLatMap* pMap);	
	BOOL GetEarliestCacheFileName(char* pFileName);

	BOOL				m_bCollectThreadliveFlag;

	set<string> 	m_CacheFileSet;

	TUserState2*	m_pUserState2;
	BOOL			m_bEnableQueryFlag;
	CC_LonLatMap 	m_CcLonLatMap;
	U64				m_CCnums;
	
	virtual BOOL OnMsg(TRawMsg * msg,IMsg * remote_src);
	BOOL TaskExecuteInit();
	void QueryCore();
	BOOL HandleResponseData( TCCQueryRSLTMsg2* msg );
	BOOL Filter(TUserState2* pstru);
	
};


class CRecordThread : public CWorkThread
{
public:
	CRecordThread();
	~CRecordThread();

private:

	I32 	m_iQueryNums;
	Arrary_AesResult* m_pAesResult;
	Arrary_RepResult* m_pRepResult;
	virtual BOOL OnMsg(TRawMsg * msg,IMsg * remote_src);
	BOOL TaskExecuteInit();
	void QueryCore();
	BOOL HandleResponseData( TCCQueryRSLTMsg2* msg );
	void HandleEncrypt(TCCQueryRSLTMsg2* msg);
	BOOL Filter(TUserState2* pstru);
};

typedef map<U64,string> PhoneCellCodeMap;
class CPhoneTouchThread : public CWorkThread
{
public:
	CPhoneTouchThread();
	CPhoneTouchThread(IMsg * pRemote);
	~CPhoneTouchThread();

private:

	PhoneCellCodeMap 	m_PhoneCCMap;
	IMsg * m_pIn;
	U32	m_MaxWriteNum;

	virtual BOOL OnMsg(TRawMsg * msg,IMsg * remote_src);
	BOOL TaskExecuteInit();
	void QueryCore();
	BOOL HandleResponseData( TCoreNotifyMsg* msg );

};





#endif//

