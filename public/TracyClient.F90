module tracy
  use, intrinsic :: iso_c_binding, only: c_ptr, c_loc, c_char, c_null_char, &
    & c_size_t, c_int8_t, c_int16_t, c_int32_t, c_int64_t, c_int, c_float, c_double, c_null_ptr
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

  interface
    function impl_tracy_alloc_srcloc(line, source, sourceSz, function_name, functionSz, color) &
            bind(C, name="___tracy_alloc_srcloc")
      import
      integer(c_int64_t) :: impl_tracy_alloc_srcloc
      integer(c_int32_t), intent(in), value :: line
      type(c_ptr), intent(in) :: source
      integer(c_size_t), intent(in), value :: sourceSz
      type(c_ptr), intent(in) :: function_name
      integer(c_size_t), intent(in), value :: functionSz
      integer(c_int32_t), intent(in), value :: color
    end function impl_tracy_alloc_srcloc
    function impl_tracy_alloc_srcloc_name(line, source, sourceSz, function_name, functionSz, zone_name, nameSz, color) &
            bind(C, name="___tracy_alloc_srcloc_name")
      import
      integer(c_int64_t) :: impl_tracy_alloc_srcloc_name
      integer(c_int32_t), intent(in), value :: line
      type(c_ptr), intent(in) :: source
      integer(c_size_t), intent(in), value :: sourceSz
      type(c_ptr), intent(in) :: function_name
      integer(c_size_t), intent(in), value :: functionSz
      type(c_ptr), intent(in) :: zone_name
      integer(c_size_t), intent(in), value :: nameSz
      integer(c_int32_t), intent(in), value :: color
    end function impl_tracy_alloc_srcloc_name
  end interface

  interface
    type(tracy_c_zone_context) function impl_tracy_emit_zone_begin_callstack(srcloc, depth, active) &
            bind(C, name="___tracy_emit_zone_begin_callstack")
      import
      type(tracy_source_location_data), intent(in) :: srcloc
      integer(c_int32_t), intent(in), value :: depth
      integer(c_int32_t), intent(in), value :: active
    end function impl_tracy_emit_zone_begin_callstack
    type(tracy_c_zone_context) function impl_tracy_emit_zone_begin_alloc_callstack(srcloc, depth, active) &
            bind(C, name="___tracy_emit_zone_begin_alloc_callstack")
      import
      integer(c_int64_t), intent(in), value :: srcloc
      integer(c_int32_t), intent(in), value :: depth
      integer(c_int32_t), intent(in), value :: active
    end function impl_tracy_emit_zone_begin_alloc_callstack
  end interface
  interface tracy_zone_begin
    module procedure tracy_emit_zone_begin_id, tracy_emit_zone_begin_type
  end interface tracy_zone_begin

  interface
    subroutine tracy_zone_end(ctx) bind(C, name="___tracy_emit_zone_end")
      import
      type(tracy_c_zone_context), intent(in), value :: ctx
    end subroutine tracy_zone_end
  end interface

  interface
    subroutine tracy_emit_zone_text(ctx, txt, size) bind(C, name="___tracy_emit_zone_text")
      import
      type(tracy_c_zone_context), intent(in), value :: ctx
      type(c_ptr), intent(in) :: txt
      integer(c_size_t), intent(in), value :: size
    end subroutine tracy_emit_zone_text
    subroutine tracy_emit_zone_name(ctx, txt, size) bind(C, name="___tracy_emit_zone_name")
      import
      type(tracy_c_zone_context), intent(in), value :: ctx
      type(c_ptr), intent(in) :: txt
      integer(c_size_t), intent(in), value :: size
    end subroutine tracy_emit_zone_name
    subroutine tracy_emit_zone_color(ctx, color) bind(C, name="___tracy_emit_zone_color")
      import
      type(tracy_c_zone_context), intent(in), value :: ctx
      integer(c_int32_t), intent(in), value :: color
    end subroutine tracy_emit_zone_color
    subroutine tracy_emit_zone_value(ctx, value) bind(C, name="___tracy_emit_zone_value")
      import
      type(tracy_c_zone_context), intent(in), value :: ctx
      integer(c_int64_t), intent(in), value :: value
    end subroutine tracy_emit_zone_value
  end interface

  ! GPU is not supported yet

  interface
    function impl_tracy_connected() bind(C, name="___tracy_connected")
      import
      integer(c_int32_t) :: impl_tracy_connected
    end function impl_tracy_connected
  end interface

  interface
    subroutine impl_tracy_emit_memory_alloc_callstack(ptr, size, depth, secure) &
            bind(C, name="___tracy_emit_memory_alloc_callstack")
        import
        type(c_ptr), intent(in) :: ptr
        integer(c_size_t), intent(in), value :: size
        integer(c_int32_t), intent(in), value :: depth
        integer(c_int32_t), intent(in), value :: secure
    end subroutine impl_tracy_emit_memory_alloc_callstack
    subroutine impl_tracy_emit_memory_alloc_callstack_named(ptr, size, depth, secure, name) &
            bind(C, name="___tracy_emit_memory_alloc_callstack_named")
        import
        type(c_ptr), intent(in) :: ptr
        integer(c_size_t), intent(in), value :: size
        integer(c_int32_t), intent(in), value :: depth
        integer(c_int32_t), intent(in), value :: secure
        type(c_ptr), intent(in) :: name
    end subroutine impl_tracy_emit_memory_alloc_callstack_named
    subroutine impl_tracy_emit_memory_free_callstack(ptr, depth, secure) &
            bind(C, name="___tracy_emit_memory_free_callstack")
        import
        type(c_ptr), intent(in) :: ptr
        integer(c_int32_t), intent(in), value :: depth
        integer(c_int32_t), intent(in), value :: secure
    end subroutine impl_tracy_emit_memory_free_callstack
    subroutine impl_tracy_emit_memory_free_callstack_named(ptr, depth, secure, name) &
            bind(C, name="___tracy_emit_memory_free_callstack_named")
        import
        type(c_ptr), intent(in) :: ptr
        integer(c_int32_t), intent(in), value :: depth
        integer(c_int32_t), intent(in), value :: secure
        type(c_ptr), intent(in) :: name
    end subroutine impl_tracy_emit_memory_free_callstack_named
    subroutine impl_tracy_emit_memory_discard_callstack(name, secure, depth) &
            bind(C, name="___tracy_emit_memory_discard_callstack")
        import
        type(c_ptr), intent(in) :: name
        integer(c_int32_t), intent(in), value :: secure
        integer(c_int32_t), intent(in), value :: depth
    end subroutine impl_tracy_emit_memory_discard_callstack
  end interface

  interface
    subroutine impl_tracy_emit_message(txt, size, depth) &
            bind(C, name="___tracy_emit_message")
        import
        type(c_ptr), intent(in) :: txt
        integer(c_size_t), value :: size
        integer(c_int32_t), value :: depth
    end subroutine impl_tracy_emit_message
    subroutine impl_tracy_emit_messageC(txt, size, color, depth) &
            bind(C, name="___tracy_emit_messageC")
        import
        type(c_ptr), intent(in) :: txt
        integer(c_size_t), value :: size
        integer(c_int32_t), value :: color
        integer(c_int32_t), value :: depth
    end subroutine impl_tracy_emit_messageC
    subroutine impl_tracy_emit_message_appinfo(txt, size) &
            bind(C, name="___tracy_emit_message_appinfo")
        import
        type(c_ptr), intent(in) :: txt
        integer(c_size_t), value :: size
    end subroutine impl_tracy_emit_message_appinfo
  end interface

  interface
    subroutine impl_tracy_emit_frame_mark(name) &
            bind(C, name="___tracy_emit_frame_mark")
        import
        type(c_ptr), intent(in) :: name
    end subroutine impl_tracy_emit_frame_mark
    subroutine impl_tracy_emit_frame_mark_start(name) &
            bind(C, name="___tracy_emit_frame_mark_start")
        import
        type(c_ptr), intent(in) :: name
    end subroutine impl_tracy_emit_frame_mark_start
    subroutine impl_tracy_emit_frame_mark_end(name) &
            bind(C, name="___tracy_emit_frame_mark_end")
        import
        type(c_ptr), intent(in) :: name
    end subroutine impl_tracy_emit_frame_mark_end
  end interface

  interface
    subroutine impl_tracy_emit_frame_image(image, w, h, offset, flip) &
            bind(C, name="___tracy_emit_frame_image")
        import
        type(c_ptr), intent(in) :: image
        integer(c_int16_t), intent(in), value :: w
        integer(c_int16_t), intent(in), value :: h
        integer(c_int8_t), intent(in), value :: offset
        integer(c_int32_t), intent(in), value :: flip
    end subroutine impl_tracy_emit_frame_image
  end interface

  interface
    subroutine impl_tracy_emit_plot_int8(name, val) &
            bind(C, name="___tracy_emit_plot_int")
        import
        type(c_ptr), intent(in) :: name
        integer(c_int64_t), value :: val
    end subroutine impl_tracy_emit_plot_int8
    subroutine impl_tracy_emit_plot_real4(name, val) &
            bind(C, name="___tracy_emit_plot_float")
        import
        type(c_ptr), intent(in) :: name
        real(c_float), value :: val
    end subroutine impl_tracy_emit_plot_real4
    subroutine impl_tracy_emit_plot_real8(name, val) &
            bind(C, name="___tracy_emit_plot")
        import
        type(c_ptr), intent(in) :: name
        real(c_double), value :: val
    end subroutine impl_tracy_emit_plot_real8
  end interface
  interface tracy_plot
    module procedure tracy_plot_int8, tracy_plot_real4, tracy_plot_real8
  end interface tracy_plot
  interface
    subroutine impl_tracy_emit_plot_config(name, type, step, fill, color) &
            bind(C, name="___tracy_emit_plot_config")
        import
        type(c_ptr), intent(in) :: name
        integer(c_int32_t), intent(in), value :: type
        integer(c_int32_t), intent(in), value :: step
        integer(c_int32_t), intent(in), value :: fill
        integer(c_int32_t), intent(in), value :: color
    end subroutine impl_tracy_emit_plot_config
  end interface

  !
  public :: tracy_c_zone_context
  !
  public :: tracy_set_thread_name
  public :: tracy_startup_profiler, tracy_shutdown_profiler, tracy_profiler_started
  public :: tracy_connected
  public :: tracy_appinfo
  public :: tracy_alloc_srcloc
  public :: tracy_zone_begin, tracy_zone_end
  public :: tracy_zone_set_properties
  public :: tracy_frame_mark, tracy_frame_start, tracy_frame_end
  public :: tracy_memory_alloc, tracy_memory_free, tracy_memory_discard
  public :: tracy_message
  public :: tracy_image
  public :: tracy_plot_config, tracy_plot
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

  integer(c_int64_t) function tracy_alloc_srcloc(line, source, function_name, zone_name, color)
    integer(c_int32_t), intent(in) :: line
    character(kind=c_char, len=*), target, intent(in) :: source, function_name
    character(kind=c_char, len=*), target, intent(in), optional :: zone_name
    integer(c_int32_t), intent(in), optional :: color
    !
    integer(c_int32_t) :: color_
    !
    color_ = 0_c_int32_t
    if (present(color)) color_ = color
    if (present(zone_name)) then
      tracy_alloc_srcloc = impl_tracy_alloc_srcloc_name(line, &
            c_loc(source), len(source, kind=c_size_t), &
            c_loc(function_name), len(function_name, kind=c_size_t), &
            c_loc(zone_name), len(zone_name, kind=c_size_t), &
            color_)
    else
      tracy_alloc_srcloc = impl_tracy_alloc_srcloc(line, &
            c_loc(source), len(source, kind=c_size_t), &
            c_loc(function_name), len(function_name, kind=c_size_t), &
            color_)
    endif
  end function tracy_alloc_srcloc

  type(tracy_c_zone_context) function tracy_emit_zone_begin_id(srcloc, depth, active)
    integer(c_int64_t), intent(in) :: srcloc
    integer(c_int32_t), intent(in), optional :: depth
    logical(1), intent(in), optional :: active
    !
    integer(c_int32_t) :: depth_
    integer(c_int32_t) :: active_
    active_ = 1_c_int32_t
    depth_ = 0_c_int32_t
    if (present(active)) then
      if (active) then
        active_ = 1_c_int32_t
      else
        active_ = 0_c_int32_t
      end if
    end if
    if (present(depth)) depth_ = depth
    tracy_emit_zone_begin_id = impl_tracy_emit_zone_begin_alloc_callstack(srcloc, depth_, active_)
  end function tracy_emit_zone_begin_id
  type(tracy_c_zone_context) function tracy_emit_zone_begin_type(srcloc, depth, active)
    type(tracy_source_location_data), intent(in) :: srcloc
    integer(c_int32_t), intent(in), optional :: depth
    logical(1), intent(in), optional :: active
    !
    integer(c_int32_t) :: depth_
    integer(c_int32_t) :: active_
    active_ = 1_c_int32_t
    depth_ = 0_c_int32_t
    if (present(active)) then
      if (active) then
        active_ = 1_c_int32_t
      else
        active_ = 0_c_int32_t
      end if
    end if
    if (present(depth)) depth_ = depth
    tracy_emit_zone_begin_type = impl_tracy_emit_zone_begin_callstack(srcloc, depth_, active_)
  end function tracy_emit_zone_begin_type

  subroutine tracy_zone_set_properties(ctx, text, name, color, value)
    type(tracy_c_zone_context), intent(in), value :: ctx
    character(kind=c_char, len=*), target, intent(in), optional :: text
    character(kind=c_char, len=*), target, intent(in), optional :: name
    integer(c_int32_t), target, intent(in), optional :: color
    integer(c_int64_t), target, intent(in), optional :: value
    if (present(text)) then
      call tracy_emit_zone_text(ctx, c_loc(text), len(text, kind=c_size_t))
    end if
    if (present(name)) then
      call tracy_emit_zone_name(ctx, c_loc(name), len(name, kind=c_size_t))
    end if
    if (present(color)) then
      call tracy_emit_zone_color(ctx, color)
    end if
    if (present(value)) then
      call tracy_emit_zone_value(ctx, value)
    end if
  end subroutine tracy_zone_set_properties

  logical(1) function tracy_connected()
    tracy_connected = impl_tracy_connected() /= 0_c_int32_t
  end function tracy_connected

  subroutine tracy_memory_alloc(ptr, size, name, depth, secure)
    type(c_ptr), intent(in) :: ptr
    integer(c_size_t), intent(in) :: size
    character(kind=c_char, len=*), target, intent(in), optional :: name
    integer(c_int32_t), intent(in), optional :: depth
    logical(1), intent(in), optional :: secure
    !
    integer(c_int32_t) :: depth_, secure_
    secure_ = 0_c_int32_t
    depth_ = 0_c_int32_t
    if (present(secure)) then
      if (secure) secure_ = 1_c_int32_t
    end if
    if (present(depth)) depth_ = depth
    if (present(name)) then
      call impl_tracy_emit_memory_alloc_callstack_named(ptr, size, depth_, secure_, c_loc(name))
    else
      call impl_tracy_emit_memory_alloc_callstack(ptr, size, depth_, secure_)
    end if
  end subroutine tracy_memory_alloc
  subroutine tracy_memory_free(ptr, name, depth, secure)
    type(c_ptr), intent(in) :: ptr
    character(kind=c_char, len=*), target, intent(in), optional :: name
    integer(c_int32_t), intent(in), optional :: depth
    logical(1), intent(in), optional :: secure
    !
    integer(c_int32_t) :: depth_, secure_
    secure_ = 0_c_int32_t
    depth_ = 0_c_int32_t
    if (present(secure)) then
      if (secure) secure_ = 1_c_int32_t
    end if
    if (present(depth)) depth_ = depth
    if (present(name)) then
      call impl_tracy_emit_memory_free_callstack_named(ptr, depth_, secure_, c_loc(name))
    else
      call impl_tracy_emit_memory_free_callstack(ptr, depth_, secure_)
    end if
  end subroutine tracy_memory_free
  subroutine tracy_memory_discard(name, depth, secure)
    character(kind=c_char, len=*), target, intent(in) :: name
    integer(c_int32_t), intent(in), optional :: depth
    logical(1), intent(in), optional :: secure
    !
    integer(c_int32_t) :: depth_, secure_
    secure_ = 0_c_int32_t
    depth_ = 0_c_int32_t
    if (present(secure)) then
      if (secure) secure_ = 1_c_int32_t
    end if
    if (present(depth)) depth_ = depth
    call impl_tracy_emit_memory_discard_callstack(c_loc(name), depth_, secure_)
  end subroutine tracy_memory_discard

  subroutine tracy_message(msg, color, depth)
    character(kind=c_char, len=*), target, intent(in) :: msg
    integer(c_int32_t), intent(in), optional :: color
    integer(c_int32_t), intent(in), optional :: depth
    !
    integer(c_int32_t) :: depth_
    depth_ = 0_c_int32_t
    if (present(depth)) depth_ = depth
    if (present(color)) then
      call impl_tracy_emit_messageC(c_loc(msg), len(msg, kind=c_size_t), color, depth_)
    else
      call impl_tracy_emit_message(c_loc(msg), len(msg, kind=c_size_t), depth_)
    end if
  end subroutine tracy_message

  subroutine tracy_appinfo(info)
    character(kind=c_char, len=*), target, intent(in) :: info
    call impl_tracy_emit_message_appinfo(c_loc(info), len(info, kind=c_size_t))
  end subroutine tracy_appinfo

  subroutine tracy_frame_mark(name)
    character(kind=c_char, len=*), target, intent(in), optional :: name
    if (present(name)) then
      call impl_tracy_emit_frame_mark(c_loc(name))
    else
      call impl_tracy_emit_frame_mark(c_null_ptr)
    end if
  end subroutine tracy_frame_mark
  subroutine tracy_frame_start(name)
    character(kind=c_char, len=*), target, intent(in), optional :: name
    if (present(name)) then
      call impl_tracy_emit_frame_mark_start(c_loc(name))
    else
      call impl_tracy_emit_frame_mark_start(c_null_ptr)
    end if
  end subroutine tracy_frame_start
  subroutine tracy_frame_end(name)
    character(kind=c_char, len=*), target, intent(in), optional :: name
    if (present(name)) then
      call impl_tracy_emit_frame_mark_end(c_loc(name))
    else
      call impl_tracy_emit_frame_mark_end(c_null_ptr)
    end if
  end subroutine tracy_frame_end

  subroutine tracy_image(image, w, h, offset, flip)
    type(c_ptr), intent(in) :: image
    integer(c_int16_t), intent(in) :: w, h
    integer(c_int8_t), intent(in), optional :: offset
    logical(1), intent(in), optional :: flip
    !
    integer(c_int32_t) :: flip_
    integer(c_int8_t) :: offset_
    flip_ = 0_c_int32_t
    offset_ = 0_c_int8_t
    if (present(flip)) then
      if (flip) flip_ = 1_c_int32_t
    end if
    if (present(offset)) offset_ = offset
    call impl_tracy_emit_frame_image(image, w, h, offset_, flip_)
  end subroutine tracy_image

  subroutine tracy_plot_int8(name, val)
    character(kind=c_char, len=*), target, intent(in) :: name
    integer(c_int64_t) :: val
    call impl_tracy_emit_plot_int8(c_loc(name), val)
  end subroutine tracy_plot_int8
  subroutine tracy_plot_real4(name, val)
    character(kind=c_char, len=*), target, intent(in) :: name
    real(c_float) :: val
    call impl_tracy_emit_plot_real4(c_loc(name), val)
  end subroutine tracy_plot_real4
  subroutine tracy_plot_real8(name, val)
    character(kind=c_char, len=*), target, intent(in) :: name
    real(c_double) :: val
    call impl_tracy_emit_plot_real8(c_loc(name), val)
  end subroutine tracy_plot_real8

  subroutine tracy_plot_config(name, type, step, fill, color)
    character(kind=c_char, len=*), target, intent(in) :: name
    integer(c_int32_t), intent(in), optional :: type
    logical(1), intent(in), optional :: step
    logical(1), intent(in), optional :: fill
    integer(c_int32_t), intent(in), optional :: color
    !
    integer(c_int32_t) :: type_, step_, fill_, color_
    type_ = 0_c_int32_t
    step_ = 0_c_int32_t
    fill_ = 1_c_int32_t
    color_ = 0_c_int32_t
    if (present(type)) type_ = type
    if (present(step)) then
      if (step) step_ = 1_c_int32_t
    end if
    if (present(fill)) then
      if (.not. fill) fill_ = 0_c_int32_t
    end if
    if (present(color)) color_ = color
    call impl_tracy_emit_plot_config(c_loc(name), type_, step_, fill_, color_)
  end subroutine tracy_plot_config
end module tracy
