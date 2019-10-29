// Copyright (c) 2013 Doug Binks
// 
// This software is provided 'as-is', without any express or implied
// warranty. In no event will the authors be held liable for any damages
// arising from the use of this software.
// 
// Permission is granted to anyone to use this software for any purpose,
// including commercial applications, and to alter it and redistribute it
// freely, subject to the following restrictions:
// 
// 1. The origin of this software must not be misrepresented; you must not
//    claim that you wrote the original software. If you use this software
//    in a product, an acknowledgement in the product documentation would be
//    appreciated but is not required.
// 2. Altered source versions must be plainly marked as such, and must not be
//    misrepresented as being the original software.
// 3. This notice may not be removed or altered from any source distribution.

#include "TaskScheduler_c.h"
#include "TaskScheduler.h"

#include <assert.h>

using namespace enki;

struct enkiTaskScheduler : TaskScheduler
{
};

struct enkiTaskSet : ITaskSet
{
	enkiTaskSet( enkiTaskExecuteRange taskFun_ ) : taskFun(taskFun_), pArgs(NULL) {}

	virtual void ExecuteRange( TaskSetPartition range, uint32_t threadnum  )
	{
		taskFun( range.start, range.end, threadnum, pArgs );
	}

	enkiTaskExecuteRange taskFun;
	void* pArgs;
};

enkiTaskScheduler*	enkiNewTaskScheduler()
{
	enkiTaskScheduler* pETS = new enkiTaskScheduler();
    return pETS;
}

void	            enkiInitTaskScheduler(  enkiTaskScheduler* pETS_ )
{
    pETS_->Initialize();
}

void	            enkiInitTaskSchedulerNumThreads(  enkiTaskScheduler* pETS_, uint32_t numThreads_ )
{
    pETS_->Initialize( numThreads_ );
}

void				enkiDeleteTaskScheduler( enkiTaskScheduler* pETS_ )
{
	delete pETS_;
}

enkiTaskSet*		enkiCreateTaskSet( enkiTaskScheduler* pETS_, enkiTaskExecuteRange taskFunc_  )
{
	return new enkiTaskSet( taskFunc_ );
}

void                enkiDeleteTaskSet( enkiTaskSet* pTaskSet_ )
{
	delete pTaskSet_;
}

void				enkiAddTaskSetToPipe( enkiTaskScheduler* pETS_, enkiTaskSet* pTaskSet_, void* pArgs_, uint32_t setSize_ )
{
	assert( pTaskSet_ );
	assert( pTaskSet_->taskFun );

	pTaskSet_->m_SetSize = setSize_;
	pTaskSet_->pArgs = pArgs_;
	pETS_->AddTaskSetToPipe( pTaskSet_ );
}

void enkiAddTaskSetToPipeMinRange(enkiTaskScheduler * pETS_, enkiTaskSet * pTaskSet_, void * pArgs_, uint32_t setSize_, uint32_t minRange_)
{
	assert( pTaskSet_ );
	assert( pTaskSet_->taskFun );

	pTaskSet_->m_SetSize = setSize_;
	pTaskSet_->m_MinRange = minRange_;
	pTaskSet_->pArgs = pArgs_;
	pETS_->AddTaskSetToPipe( pTaskSet_ );
}

int				enkiIsTaskSetComplete( enkiTaskScheduler* pETS_, enkiTaskSet* pTaskSet_ )
{
	assert( pTaskSet_ );
	return ( pTaskSet_->GetIsComplete() ) ? 1 : 0;
}

void				enkiWaitForTaskSet( enkiTaskScheduler* pETS_, enkiTaskSet* pTaskSet_ )
{
	pETS_->WaitforTaskSet( pTaskSet_ );
}

void				enkiWaitForAll( enkiTaskScheduler* pETS_ )
{
	pETS_->WaitforAll();
}


uint32_t			enkiGetNumTaskThreads( enkiTaskScheduler* pETS_ )
{
	return pETS_->GetNumTaskThreads();
}

enkiProfilerCallbacks*	enkiGetProfilerCallbacks( enkiTaskScheduler* pETS_ )
{
    assert( sizeof(enkiProfilerCallbacks) == sizeof(enki::ProfilerCallbacks) );
    return (enkiProfilerCallbacks*)pETS_->GetProfilerCallbacks();
}

