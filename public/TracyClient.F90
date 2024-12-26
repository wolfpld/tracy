module tracy
  use, intrinsic :: iso_c_binding, only: c_ptr, c_loc, c_char, c_null_char
  implicit none
  private
  ! skipped: TracyPlotFormatEnum
  interface
    subroutine impl_tracy_set_thread_name(name) bind(C, name="___tracy_set_thread_name")
      import
      type(c_ptr) :: name
    end subroutine impl_tracy_set_thread_name
  end interface
  !
  public :: tracy_set_thread_name
contains
  subroutine tracy_set_thread_name(name)
    character(kind=c_char, len=*), intent(in) :: name
    character(kind=c_char, len=:), allocatable, target :: alloc_name
    allocate(character(kind=c_char, len=len(name) + 1) :: alloc_name)
    alloc_name = name // c_null_char
    call impl_tracy_set_thread_name(c_loc(alloc_name))
  end subroutine tracy_set_thread_name
end module tracy
