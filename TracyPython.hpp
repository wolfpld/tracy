#ifndef __TRACYPYTHON_HPP__
#define __TRACYPYTHON_HPP__

// Include this file after you include python headers.

#ifndef TRACY_ENABLE

#define TRACY_ENABLE_PYTHON_PROFILE
#define TRACY_DISABLE_PYTHON_PROFILE

#else

namespace tracy
{

	inline int PythonZoneBeginN(const char* file_name, const char* func_name, int line_no)
	{
		TracyLfqPrepareC(tracy::QueueType::ZoneBeginAllocSrcLoc);
		const auto srcloc = tracy::Profiler::AllocSourceLocation(line_no, file_name, func_name, "", 0);
		tracy::MemWrite(&item->zoneBegin.time, tracy::Profiler::GetTime());
		tracy::MemWrite(&item->zoneBegin.srcloc, srcloc);
		TracyLfqCommitC;
		return 0;
}

	inline int PythonZoneEnd()
	{
		TracyLfqPrepareC(tracy::QueueType::ZoneEnd);
		tracy::MemWrite(&item->zoneEnd.time, tracy::Profiler::GetTime());
		TracyLfqCommitC;
		return 0;
	}

	inline int tracer(PyObject* self, PyFrameObject* f, int what, PyObject* args)
	{
		static const char* file_name;
		static const char* func_name;
		static int line_no = -1;

		switch (what)
		{
			case PyTrace_CALL:
			{
#if PY_MAJOR_VERSION == 3
				file_name = PyUnicode_AsUTF8((f->f_code->co_filename));
				func_name = PyUnicode_AsUTF8((f->f_code->co_name));
#else
				file_name = PyString_AsString((f->f_code->co_filename));
				func_name = PyString_AsString((f->f_code->co_name));
#endif
				line_no = f->f_code->co_firstlineno;
				PythonZoneBeginN(file_name, func_name, line_no);
			}
			break;
			case PyTrace_RETURN:
			{
				PythonZoneEnd();
			}
			break;
			/* ignore PyTrace_EXCEPTION */
			default: break;
		}
		return 0;
	}
}

#define TRACY_ENABLE_PYTHON_PROFILE PyEval_SetProfile(tracy::tracer, nullptr);
#define TRACY_DISABLE_PYTHON_PROFILE PyEval_SetProfile(nullptr, nullptr);
#endif

#endif