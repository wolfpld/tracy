module tracy
  use, intrinsic :: iso_c_binding, only: c_ptr, c_loc, c_char, c_null_char, &
    & c_int8_t, c_int16_t, c_int32_t, c_int64_t, c_int, c_float
  implicit none
  private
  ! skipped: TracyPlotFormatEnum
  interface
    subroutine impl_tracy_set_thread_name(name) bind(C, name="___tracy_set_thread_name")
      import
      type(c_ptr) :: name
    end subroutine impl_tracy_set_thread_name
  end interface

  type, bind(C) :: tracy_source_location_data
    type(c_ptr) :: name
    type(c_ptr) :: function
    type(c_ptr) :: file
    integer(c_int32_t) :: line
    integer(c_int32_t) :: color
  end type

  type, bind(C) :: tracy_c_zone_context
    integer(c_int32_t) :: id
    integer(c_int32_t) :: active
  end type

  type, bind(C) :: tracy_gpu_time_data
    integer(c_int64_t) :: gpuTime
    integer(c_int16_t) :: queryId
    integer(c_int8_t) :: context
  end type

  type, bind(C) :: tracy_gpu_zone_begin_data
    integer(c_int64_t) :: srcloc
    integer(c_int16_t) :: queryId
    integer(c_int8_t) :: context
  end type

  type, bind(C) :: tracy_gpu_zone_begin_callstack_data
    integer(c_int64_t) :: srcloc
    integer(c_int32_t) :: depth
    integer(c_int16_t) :: queryId
    integer(c_int8_t) :: context
  end type

  type, bind(C) :: tracy_gpu_zone_end_data
    integer(c_int16_t) :: queryId
    integer(c_int8_t) :: context
  end type

  type, bind(C) :: tracy_gpu_new_context_data
    integer(c_int64_t) :: gpuTime
    real(c_float) :: period
    integer(c_int8_t) :: context
    integer(c_int8_t) :: flags
    integer(c_int8_t) :: type
  end type

  type, bind(C) :: tracy_gpu_context_name_data
    integer(c_int8_t) :: context
    type(c_ptr) :: name
    integer(c_int16_t) :: len
  end type

  type, bind(C) :: tracy_gpu_calibration_data
    integer(c_int64_t) :: gpuTime
    integer(c_int64_t) :: cpuDelta
    integer(c_int8_t) :: context
  end type

  type, bind(C) :: tracy_gpu_time_sync_data
    integer(c_int64_t) :: gpuTime
    integer(c_int8_t) :: context
  end type

  ! tracy_lockable_context_data and related stuff is missed since Fortran does not have support of mutexes

  interface
    subroutine tracy_startup_profiler() bind(C, name="___tracy_startup_profiler")
    end subroutine tracy_startup_profiler
    subroutine tracy_shutdown_profiler() bind(C, name="___tracy_shutdown_profiler")
    end subroutine tracy_shutdown_profiler
    function impl_tracy_profiler_started() bind(C, name="___tracy_profiler_started")
      import
      integer(c_int32_t) :: impl_tracy_profiler_started
    end function impl_tracy_profiler_started
  end interface

  !
  public :: tracy_c_zone_context
  !
  public :: tracy_set_thread_name
  public :: tracy_startup_profiler, tracy_shutdown_profiler, tracy_profiler_started
contains
  subroutine tracy_set_thread_name(name)
    character(kind=c_char, len=*), intent(in) :: name
    character(kind=c_char, len=:), allocatable, target :: alloc_name
    allocate(character(kind=c_char, len=len(name) + 1) :: alloc_name)
    alloc_name = name // c_null_char
    call impl_tracy_set_thread_name(c_loc(alloc_name))
  end subroutine tracy_set_thread_name

  logical(1) function tracy_profiler_started()
    tracy_profiler_started = impl_tracy_profiler_started() /= 0_c_int
  end function tracy_profiler_started
end module tracy
