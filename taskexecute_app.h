#ifndef __AREASMS_TASKEXECUTE_APP_H__   
#define __AREASMS_TASKEXECUTE_APP_H__ 

#include <framework.h>


#define AGENT_NAME_TASK_DISPATCH 			"taskexecute2dispatch"
#define AGENT_NAME_OIDD_CORE				"TaskExecute2Core"




class CTaskExecute : public CApplication
{
public:
	CTaskExecute();
	~CTaskExecute();
protected:
	
	virtual void GetCfgSubscribeInfo(
				CCfgPathPairList &paths, CCfgDynamicSubscriberList &dynamic_nodes);
	
	virtual BOOL Initialize();
	virtual BOOL Running();
	virtual BOOL Terminate();
	
};



#endif//__AREASMS_TASKEXECUTE_APP_H__
