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

#include <assert.h>

#include "TaskScheduler.h"
#include "LockLessMultiReadPipe.h"



using namespace enki;


static const uint32_t PIPESIZE_LOG2              = 8;
static const uint32_t SPIN_COUNT                 = 100;
static const uint32_t SPIN_BACKOFF_MULTIPLIER    = 10;
static const uint32_t MAX_NUM_INITIAL_PARTITIONS = 8;

// each software thread gets it's own copy of gtl_threadNum, so this is safe to use as a static variable
static THREAD_LOCAL uint32_t                             gtl_threadNum       = 0;

namespace enki 
{
	struct SubTaskSet
	{
		ITaskSet*           pTask;
		TaskSetPartition    partition;
	};

	// we derive class TaskPipe rather than typedef to get forward declaration working easily
	class TaskPipe : public LockLessMultiReadPipe<PIPESIZE_LOG2,enki::SubTaskSet> {};

	struct ThreadArgs
	{
		uint32_t		threadNum;
		TaskScheduler*  pTaskScheduler;
	};
}

namespace
{
	SubTaskSet       SplitTask( SubTaskSet& subTask_, uint32_t rangeToSplit_ )
	{
		SubTaskSet splitTask = subTask_;
		uint32_t rangeLeft = subTask_.partition.end - subTask_.partition.start;

        if( rangeToSplit_ > rangeLeft )
        {
            rangeToSplit_ = rangeLeft;
        }
        splitTask.partition.end = subTask_.partition.start + rangeToSplit_;
		subTask_.partition.start = splitTask.partition.end;
		return splitTask;
	}

	#if defined _WIN32
		#if defined _M_IX86  || defined _M_X64
			#pragma intrinsic(_mm_pause)
			inline void Pause() { _mm_pause(); }
		#endif
	#elif defined __i386__ || defined __x86_64__
		inline void Pause() { __asm__ __volatile__("pause;"); }
	#else
		inline void Pause() { ;} // may have NOP or yield equiv
	#endif
}


static void SafeCallback(ProfilerCallbackFunc func_, uint32_t threadnum_)
{
	if( func_ )
	{
		func_(threadnum_);
	}
}

ProfilerCallbacks* TaskScheduler::GetProfilerCallbacks()
{
	return &m_ProfilerCallbacks;
}

THREADFUNC_DECL TaskScheduler::TaskingThreadFunction( void* pArgs )
{
	ThreadArgs args					= *(ThreadArgs*)pArgs;
	uint32_t threadNum				= args.threadNum;
	TaskScheduler*  pTS				= args.pTaskScheduler;
    gtl_threadNum      = threadNum;

	SafeCallback( pTS->m_ProfilerCallbacks.threadStart, threadNum );
    
    uint32_t spinCount = 0;
	uint32_t hintPipeToCheck_io = threadNum + 1;	// does not need to be clamped.
    while( pTS->m_bRunning )
    {
        if(!pTS->TryRunTask( threadNum, hintPipeToCheck_io ) )
        {
            // no tasks, will spin then wait
            ++spinCount;
            if( spinCount > SPIN_COUNT )
            {
				pTS->WaitForTasks( threadNum );
				spinCount = 0;
            }
			else
			{
				uint32_t spinBackoffCount = spinCount * SPIN_BACKOFF_MULTIPLIER;
				while( spinBackoffCount )
				{
					Pause();
					--spinBackoffCount;
				}
			}
        }
        else
        {
            spinCount = 0;
        }
    }

    AtomicAdd( &pTS->m_NumThreadsRunning, -1 );
	SafeCallback( pTS->m_ProfilerCallbacks.threadStop, threadNum );

    return 0;
}


void TaskScheduler::StartThreads()
{
    if( m_bHaveThreads )
    {
        return;
    }
    m_bRunning = true;

    SemaphoreCreate( m_NewTaskSemaphore );

    // we create one less thread than m_NumThreads as the main thread counts as one
    m_pThreadNumStore = new ThreadArgs[m_NumThreads];
    m_pThreadIDs      = new threadid_t[m_NumThreads];
	m_pThreadNumStore[0].threadNum      = 0;
	m_pThreadNumStore[0].pTaskScheduler = this;
	m_pThreadIDs[0] = 0;
    m_NumThreadsWaiting = 0;
    m_NumThreadsRunning = 1;// acount for main thread
    for( uint32_t thread = 1; thread < m_NumThreads; ++thread )
    {
		m_pThreadNumStore[thread].threadNum      = thread;
		m_pThreadNumStore[thread].pTaskScheduler = this;
        ThreadCreate( &m_pThreadIDs[thread], TaskingThreadFunction, &m_pThreadNumStore[thread] );
        ++m_NumThreadsRunning;
    }

    // ensure we have sufficient tasks to equally fill either all threads including main
    // or just the threads we've launched, this is outside the firstinit as we want to be able
    // to runtime change it
	if( 1 == m_NumThreads )
	{
		m_NumPartitions = 1;
		m_NumInitialPartitions = 1;
	}
	else
	{
		m_NumPartitions = m_NumThreads * (m_NumThreads - 1);
		m_NumInitialPartitions = m_NumThreads - 1;
		if( m_NumInitialPartitions > MAX_NUM_INITIAL_PARTITIONS )
		{
			m_NumInitialPartitions = MAX_NUM_INITIAL_PARTITIONS;
		}
	}

    m_bHaveThreads = true;
}

void TaskScheduler::StopThreads( bool bWait_ )
{
    if( m_bHaveThreads )
    {
        // wait for them threads quit before deleting data
        m_bRunning = false;
        while( bWait_ && m_NumThreadsRunning > 1 )
        {
            // keep firing event to ensure all threads pick up state of m_bRunning
            SemaphoreSignal( m_NewTaskSemaphore, m_NumThreadsRunning );
        }

        for( uint32_t thread = 1; thread < m_NumThreads; ++thread )
        {
            ThreadTerminate( m_pThreadIDs[thread] );
        }

		m_NumThreads = 0;
        delete[] m_pThreadNumStore;
        delete[] m_pThreadIDs;
        m_pThreadNumStore = 0;
        m_pThreadIDs = 0;
        SemaphoreClose( m_NewTaskSemaphore );

        m_bHaveThreads = false;
		m_NumThreadsWaiting = 0;
		m_NumThreadsRunning = 0;
    }
}

bool TaskScheduler::TryRunTask( uint32_t threadNum, uint32_t& hintPipeToCheck_io_ )
{
    // check for tasks
    SubTaskSet subTask;
    bool bHaveTask = m_pPipesPerThread[ threadNum ].WriterTryReadFront( &subTask );

	uint32_t threadToCheck = hintPipeToCheck_io_;
	uint32_t checkCount = 0;
    while( !bHaveTask && checkCount < m_NumThreads )
    {
		threadToCheck = ( hintPipeToCheck_io_ + checkCount ) % m_NumThreads;
		if( threadToCheck != threadNum )
		{
			bHaveTask = m_pPipesPerThread[ threadToCheck ].ReaderTryReadBack( &subTask );
		}
		++checkCount;
    }
        
    if( bHaveTask )
    {
		// update hint, will preserve value unless actually got task from another thread.
		hintPipeToCheck_io_ = threadToCheck;

		uint32_t partitionSize = subTask.partition.end - subTask.partition.start;
		if( subTask.pTask->m_RangeToRun < partitionSize )
		{
			SubTaskSet taskToRun = SplitTask( subTask, subTask.pTask->m_RangeToRun );
			SplitAndAddTask( gtl_threadNum, subTask, subTask.pTask->m_RangeToRun, 0 );
			taskToRun.pTask->ExecuteRange( taskToRun.partition, threadNum );
			AtomicAdd( &taskToRun.pTask->m_RunningCount, -1 );
		}
		else
		{

			// the task has already been divided up by AddTaskSetToPipe, so just run it
			subTask.pTask->ExecuteRange( subTask.partition, threadNum );
			AtomicAdd( &subTask.pTask->m_RunningCount, -1 );
		}
    }

    return bHaveTask;

}

void TaskScheduler::WaitForTasks( uint32_t threadNum )
{
	// We incrememt the number of threads waiting here in order
	// to ensure that the check for tasks occurs after the increment
	// to prevent a task being added after a check, then the thread waiting.
	// This will occasionally result in threads being mistakenly awoken,
	// but they will then go back to sleep.
	AtomicAdd( &m_NumThreadsWaiting, 1 );

    bool bHaveTasks = false;
    for( uint32_t thread = 0; thread < m_NumThreads; ++thread )
    {
        if( !m_pPipesPerThread[ thread ].IsPipeEmpty() )
        {
            bHaveTasks = true;
            break;
        }
    }
    if( !bHaveTasks )
    {
        SafeCallback( m_ProfilerCallbacks.waitStart, threadNum );
        SemaphoreWait( m_NewTaskSemaphore );
        SafeCallback( m_ProfilerCallbacks.waitStop, threadNum );
    }

    int32_t prev = AtomicAdd( &m_NumThreadsWaiting, -1 );
    assert( prev != 0 );
}

void TaskScheduler::WakeThreads()
{
	SemaphoreSignal( m_NewTaskSemaphore, m_NumThreadsWaiting );
}

void TaskScheduler::SplitAndAddTask( uint32_t threadNum_, SubTaskSet subTask_,
	uint32_t rangeToSplit_, int32_t runningCountOffset_ )
{
    int32_t numAdded = 0;
    while( subTask_.partition.start != subTask_.partition.end )
    {
        SubTaskSet taskToAdd = SplitTask( subTask_, rangeToSplit_ );

        // add the partition to the pipe
        ++numAdded;
        if( !m_pPipesPerThread[ gtl_threadNum ].WriterTryWriteFront( taskToAdd ) )
        {
			if( numAdded > 1 )
			{
				WakeThreads();
			}
			// alter range to run the appropriate fraction
			if( taskToAdd.pTask->m_RangeToRun < rangeToSplit_ )
			{
				taskToAdd.partition.end = taskToAdd.partition.start + taskToAdd.pTask->m_RangeToRun;
				subTask_.partition.start = taskToAdd.partition.end;
			}
            taskToAdd.pTask->ExecuteRange( taskToAdd.partition, threadNum_ );
            --numAdded;
        }
    }

    // increment running count by number added
    AtomicAdd( &subTask_.pTask->m_RunningCount, numAdded + runningCountOffset_ );

	WakeThreads();
}

void    TaskScheduler::AddTaskSetToPipe( ITaskSet* pTaskSet )
{
	// set running count to -1 to guarantee it won't be found complete until all subtasks added
    pTaskSet->m_RunningCount = -1;

    // divide task up and add to pipe
    pTaskSet->m_RangeToRun = pTaskSet->m_SetSize / m_NumPartitions;
    if( pTaskSet->m_RangeToRun < pTaskSet->m_MinRange ) { pTaskSet->m_RangeToRun = pTaskSet->m_MinRange; }

	uint32_t rangeToSplit = pTaskSet->m_SetSize / m_NumInitialPartitions;
	if( rangeToSplit < pTaskSet->m_MinRange ) { rangeToSplit = pTaskSet->m_MinRange; }

    SubTaskSet subTask;
    subTask.pTask = pTaskSet;
    subTask.partition.start = 0;
    subTask.partition.end = pTaskSet->m_SetSize;
	SplitAndAddTask( gtl_threadNum, subTask, rangeToSplit, 1 );
}

void    TaskScheduler::WaitforTaskSet( const ITaskSet* pTaskSet )
{
	uint32_t hintPipeToCheck_io = gtl_threadNum + 1;	// does not need to be clamped.
	if( pTaskSet )
	{
		while( pTaskSet->m_RunningCount )
		{
			TryRunTask( gtl_threadNum, hintPipeToCheck_io );
			// should add a spin then wait for task completion event.
		}
	}
	else
	{
			TryRunTask( gtl_threadNum, hintPipeToCheck_io );
	}
}

void    TaskScheduler::WaitforAll()
{
    bool bHaveTasks = true;
 	uint32_t hintPipeToCheck_io = gtl_threadNum  + 1;	// does not need to be clamped.
	int32_t threadsRunning = m_NumThreadsRunning - 1;
    while( bHaveTasks || m_NumThreadsWaiting < threadsRunning )
    {
        TryRunTask( gtl_threadNum, hintPipeToCheck_io );
        bHaveTasks = false;
        for( uint32_t thread = 0; thread < m_NumThreads; ++thread )
        {
            if( !m_pPipesPerThread[ thread ].IsPipeEmpty() )
            {
                bHaveTasks = true;
                break;
            }
        }
     }
}

void    TaskScheduler::WaitforAllAndShutdown()
{
    WaitforAll();
    StopThreads(true);
	delete[] m_pPipesPerThread;
    m_pPipesPerThread = 0;
}

uint32_t        TaskScheduler::GetNumTaskThreads() const
{
    return m_NumThreads;
}

TaskScheduler::TaskScheduler()
		: m_pPipesPerThread(NULL)
		, m_NumThreads(0)
		, m_pThreadNumStore(NULL)
		, m_pThreadIDs(NULL)
		, m_bRunning(false)
		, m_NumThreadsRunning(0)
		, m_NumThreadsWaiting(0)
		, m_NumPartitions(0)
		, m_bHaveThreads(false)
{
	memset(&m_ProfilerCallbacks, 0, sizeof(m_ProfilerCallbacks));
}

TaskScheduler::~TaskScheduler()
{
    StopThreads( true ); // Stops threads, waiting for them.

    delete[] m_pPipesPerThread;
    m_pPipesPerThread = 0;
}

void    TaskScheduler::Initialize( uint32_t numThreads_ )
{
	assert( numThreads_ );
    StopThreads( true ); // Stops threads, waiting for them.
    delete[] m_pPipesPerThread;

	m_NumThreads = numThreads_;

    m_pPipesPerThread = new TaskPipe[ m_NumThreads ];

    StartThreads();
}

void   TaskScheduler::Initialize()
{
	Initialize( GetNumHardwareThreads() );
}