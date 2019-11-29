/* fileline.c -- Get file and line number information in a backtrace.
   Copyright (C) 2012-2018 Free Software Foundation, Inc.
   Written by Ian Lance Taylor, Google.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

    (1) Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.

    (2) Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in
    the documentation and/or other materials provided with the
    distribution.

    (3) The name of the author may not be used to
    endorse or promote products derived from this software without
    specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.  */

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef BSD
#  include <sys/sysctl.h>
#  include <limits.h>
#endif

#ifdef __APPLE__
#  include <mach-o/dyld.h>
#endif

#include "backtrace.hpp"
#include "internal.hpp"

#ifdef BSD
#  if !defined HAVE_GETEXECNAME && defined KERN_PROC_PATHNAME
#    define HAVE_GETEXECNAME
static char execname[PATH_MAX + 1];
static const char *
getexecname(void)
{
  size_t path_len = sizeof(execname);
  int mib[] = {
    CTL_KERN,
#if defined(__NetBSD__)
    KERN_PROC_ARGS,
    -1,
    KERN_PROC_PATHNAME,
#else
    KERN_PROC,
    KERN_PROC_PATHNAME,
    -1,
#endif
  };
  u_int miblen = sizeof(mib) / sizeof(mib[0]);
  int rc = sysctl(mib, miblen, execname, &path_len, NULL, 0);
  return rc ? NULL : execname;
}
#  endif
#endif

#if !defined HAVE_GETEXECNAME && defined __APPLE__
#  define HAVE_GETEXECNAME
static char execname[PATH_MAX + 1];
static const char *
getexecname(void)
{
  uint32_t size = sizeof(execname);
  if (_NSGetExecutablePath(execname, &size) == 0)
    return execname;
  else
    return NULL;
}
#endif

#ifndef HAVE_GETEXECNAME
#  define getexecname() NULL
#endif

namespace tracy
{

/* Initialize the fileline information from the executable.  Returns 1
   on success, 0 on failure.  */

static int
fileline_initialize (struct backtrace_state *state,
		     backtrace_error_callback error_callback, void *data)
{
  int failed;
  fileline fileline_fn;
  int pass;
  int called_error_callback;
  int descriptor;
  const char *filename;
  char buf[64];

  failed = state->fileline_initialization_failed;

  if (failed)
    {
      error_callback (data, "failed to read executable information", -1);
      return 0;
    }

  fileline_fn = state->fileline_fn;
  if (fileline_fn != NULL)
    return 1;

  /* We have not initialized the information.  Do it now.  */

  descriptor = -1;
  called_error_callback = 0;
  for (pass = 0; pass < 5; ++pass)
    {
      int does_not_exist;

      switch (pass)
	{
	case 0:
	  filename = state->filename;
	  break;
	case 1:
	  filename = getexecname ();
	  break;
	case 2:
	  filename = "/proc/self/exe";
	  break;
	case 3:
	  filename = "/proc/curproc/file";
	  break;
	case 4:
	  snprintf (buf, sizeof (buf), "/proc/%ld/object/a.out",
		    (long) getpid ());
	  filename = buf;
	  break;
	default:
	  abort ();
	}

      if (filename == NULL)
	continue;

      descriptor = backtrace_open (filename, error_callback, data,
				   &does_not_exist);
      if (descriptor < 0 && !does_not_exist)
	{
	  called_error_callback = 1;
	  break;
	}
      if (descriptor >= 0)
	break;
    }

  if (descriptor < 0)
    {
      if (!called_error_callback)
	{
	  if (state->filename != NULL)
	    error_callback (data, state->filename, ENOENT);
	  else
	    error_callback (data,
			    "libbacktrace could not find executable to open",
			    0);
	}
      failed = 1;
    }

  if (!failed)
    {
      if (!backtrace_initialize (state, filename, descriptor, error_callback,
				 data, &fileline_fn))
	failed = 1;
    }

  if (failed)
  {
    state->fileline_initialization_failed = 1;
    return 0;
  }

  state->fileline_fn = fileline_fn;

  return 1;
}

/* Given a PC, find the file name, line number, and function name.  */

int
backtrace_pcinfo (struct backtrace_state *state, uintptr_t pc,
		  backtrace_full_callback callback,
		  backtrace_error_callback error_callback, void *data)
{
  if (!fileline_initialize (state, error_callback, data))
    return 0;

  if (state->fileline_initialization_failed)
    return 0;

  return state->fileline_fn (state, pc, callback, error_callback, data);
}

/* Given a PC, find the symbol for it, and its value.  */

int
backtrace_syminfo (struct backtrace_state *state, uintptr_t pc,
		   backtrace_syminfo_callback callback,
		   backtrace_error_callback error_callback, void *data)
{
  if (!fileline_initialize (state, error_callback, data))
    return 0;

  if (state->fileline_initialization_failed)
    return 0;

  state->syminfo_fn (state, pc, callback, error_callback, data);
  return 1;
}

}
