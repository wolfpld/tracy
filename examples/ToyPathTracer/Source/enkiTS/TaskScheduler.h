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

#pragma once

#include <stdint.h>
#include "Threads.h"

namespace enki
{

	struct TaskSetPartition
	{
		uint32_t start;
		uint32_t end;
	};

	class  TaskScheduler;
	class  TaskPipe;
	struct ThreadArgs;
	struct SubTaskSet;

	// Subclass ITaskSet to create tasks.
	// TaskSets can be re-used, but check
	class ITaskSet
	{
	public:
        ITaskSet()
            : m_SetSize(1)
			, m_MinRange(1)
            , m_RunningCount(0)
			, m_RangeToRun(1)
        {}

        ITaskSet( uint32_t setSize_ )
            : m_SetSize( setSize_ )
			, m_MinRange(1)
            , m_RunningCount(0)
			, m_RangeToRun(1)
        {}

		ITaskSet( uint32_t setSize_, uint32_t minRange_ )
            : m_SetSize( setSize_ )
			, m_MinRange( minRange_ )
            , m_RunningCount(0)
			, m_RangeToRun(minRange_)
        {}

		// Execute range should be overloaded to process tasks. It will be called with a
		// range_ where range.start >= 0; range.start < range.end; and range.end < m_SetSize;
		// The range values should be mapped so that linearly processing them in order is cache friendly
		// i.e. neighbouring values should be close together.
		// threadnum should not be used for changing processing of data, it's intended purpose
		// is to allow per-thread data buckets for output.
		virtual void            ExecuteRange( TaskSetPartition range, uint32_t threadnum  ) = 0;

		// Size of set - usually the number of data items to be processed, see ExecuteRange. Defaults to 1
		uint32_t                m_SetSize;

		// Minimum size of of TaskSetPartition range when splitting a task set into partitions.
		// This should be set to a value which results in computation effort of at least 10k
		// clock cycles to minimize tast scheduler overhead.
		// NOTE: The last partition will be smaller than m_MinRange if m_SetSize is not a multiple
		// of m_MinRange.
		// Also known as grain size in literature.
		uint32_t                m_MinRange;

		bool                    GetIsComplete()
		{
			return 0 == m_RunningCount;
		}
	private:
		friend class           TaskScheduler;
		volatile int32_t        m_RunningCount;
		uint32_t                m_RangeToRun;
	};

	// TaskScheduler implements several callbacks intended for profilers
	typedef void (*ProfilerCallbackFunc)( uint32_t threadnum_ );
	struct ProfilerCallbacks
	{
		ProfilerCallbackFunc threadStart;
		ProfilerCallbackFunc threadStop;
		ProfilerCallbackFunc waitStart;
		ProfilerCallbackFunc waitStop;
	};

	class TaskScheduler
	{
	public:
		TaskScheduler();
		~TaskScheduler();

		// Call either Initialize() or Initialize( numThreads_ ) before adding tasks.

		// Initialize() will create GetNumHardwareThreads()-1 threads, which is
		// sufficient to fill the system when including the main thread.
		// Initialize can be called multiple times - it will wait for completion
		// before re-initializing.
		void			Initialize();

		// Initialize( numThreads_ ) - numThreads_ (must be > 0)
		// will create numThreads_-1 threads, as thread 0 is
		// the thread on which the initialize was called.
		void			Initialize( uint32_t numThreads_ );


		// Adds the TaskSet to pipe and returns if the pipe is not full.
		// If the pipe is full, pTaskSet is run.
		// should only be called from main thread, or within a task
		void            AddTaskSetToPipe( ITaskSet* pTaskSet );

		// Runs the TaskSets in pipe until true == pTaskSet->GetIsComplete();
		// should only be called from thread which created the taskscheduler , or within a task
		// if called with 0 it will try to run tasks, and return if none available.
		void            WaitforTaskSet( const ITaskSet* pTaskSet );

		// Waits for all task sets to complete - not guaranteed to work unless we know we
		// are in a situation where tasks aren't being continuosly added.
		void            WaitforAll();

		// Waits for all task sets to complete and shutdown threads - not guaranteed to work unless we know we
		// are in a situation where tasks aren't being continuosly added.
		void            WaitforAllAndShutdown();

		// Returns the number of threads created for running tasks + 1
		// to account for the main thread.
		uint32_t        GetNumTaskThreads() const;

		// Returns the ProfilerCallbacks structure so that it can be modified to
		// set the callbacks.
		ProfilerCallbacks* GetProfilerCallbacks();

	private:
		static THREADFUNC_DECL  TaskingThreadFunction( void* pArgs );
        void             WaitForTasks( uint32_t threadNum );
		bool             TryRunTask( uint32_t threadNum, uint32_t& hintPipeToCheck_io_ );
		void             StartThreads();
		void             StopThreads( bool bWait_ );
		void             SplitAndAddTask( uint32_t threadNum_, SubTaskSet subTask_,
										  uint32_t rangeToSplit_, int32_t runningCountOffset_ );
		void             WakeThreads();

		TaskPipe*                                                m_pPipesPerThread;

		uint32_t                                                 m_NumThreads;
		ThreadArgs*                                              m_pThreadNumStore;
		threadid_t*                                              m_pThreadIDs;
		volatile bool                                            m_bRunning;
		volatile int32_t                                         m_NumThreadsRunning;
		volatile int32_t                                         m_NumThreadsWaiting;
		uint32_t                                                 m_NumPartitions;
		uint32_t                                                 m_NumInitialPartitions;
		semaphoreid_t                                            m_NewTaskSemaphore;
		bool                                                     m_bHaveThreads;
		ProfilerCallbacks										 m_ProfilerCallbacks;

		TaskScheduler( const TaskScheduler& nocopy );
		TaskScheduler& operator=( const TaskScheduler& nocopy );
	};

}