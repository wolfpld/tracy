/*
 * This file is licensed under the 3-clause BSD license.
 *
 * Copyright (c) 2025, Ondřej Míchal <harrymichal@seznam.cz>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *   * Neither the name of the <organization> nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#define CL_TARGET_OPENCL_VERSION 300
#define CL_USE_DEPRECATED_OPENCL_1_0_APIS
#define CL_USE_DEPRECATED_OPENCL_1_1_APIS
#define CL_USE_DEPRECATED_OPENCL_1_2_APIS
#define CL_USE_DEPRECATED_OPENCL_2_0_APIS
#define CL_USE_DEPRECATED_OPENCL_2_1_APIS
#define CL_USE_DEPRECATED_OPENCL_2_2_APIS

#include <CL/cl_layer.h>

#include <tracy/tracy/Tracy.hpp>
#include <tracy/tracy/TracyOpenCL.hpp>

#define TRACY_CL_WRAP( F )                                             \
    {                                                                  \
        cl_event tracy_event;                                          \
                                                                       \
        if( event == nullptr ) event = &tracy_event;                   \
                                                                       \
        ZoneScopedCS( tracy::Color::CadetBlue, 4 );                    \
                                                                       \
        TracyCLCtx _tracy_ctx = get_tracy_cl_ctx( ( command_queue ) ); \
        if( _tracy_ctx != nullptr )                                    \
        {                                                              \
            TracyCLZone( _tracy_ctx, __func__ );                       \
            F;                                                         \
            TracyCLZoneSetEvent( *event );                             \
        }                                                              \
        else                                                           \
        {                                                              \
            F;                                                         \
        }                                                              \
    }

constexpr int tracy_cl_max_ctxs = 32;

struct context_device_ctx
{
    cl_context context;
    cl_device_id device_id;
    TracyCLCtx tracy_ctx;
};

namespace
{
struct _cl_icd_dispatch dispatch;
const struct _cl_icd_dispatch* tdispatch;

thread_local struct context_device_ctx tracy_ctxs[tracy_cl_max_ctxs];
thread_local int tracy_ctxs_nof = 0;

TracyCLCtx get_tracy_cl_ctx( cl_command_queue command_queue )
{
    thread_local uint8_t ctx_requested = 0;
    TracyCLCtx tracy_cl_ctx = nullptr;
    cl_context context;
    cl_device_id device_id;
    cl_int ctx_err, device_id_err;

    // Prevent the layer recursing into itself.
    if( ctx_requested != 0 )
        return nullptr;

    ctx_requested++;

    // Check if there is a TracyCLCtx for this combination of cl_context and cl_device_id.
    ctx_err = tdispatch->clGetCommandQueueInfo( command_queue, CL_QUEUE_CONTEXT, sizeof( cl_context ), (void*)&context,
                                                nullptr );

    device_id_err = tdispatch->clGetCommandQueueInfo( command_queue, CL_QUEUE_DEVICE, sizeof( cl_device_id ),
                                                      (void*)&device_id, nullptr );

    if( ctx_err == CL_SUCCESS && device_id_err == CL_SUCCESS )
    {
        for( int i = 0; i < tracy_ctxs_nof; i++ )
        {
            if( context != tracy_ctxs[i].context || device_id != tracy_ctxs[i].device_id ) continue;
            tracy_cl_ctx = tracy_ctxs[i].tracy_ctx;
            break;
        }

        if( tracy_cl_ctx == nullptr && tracy_ctxs_nof < tracy_cl_max_ctxs )
        {
            // Create a new TracyCLCtx.
            tracy_ctxs[tracy_ctxs_nof].context = context;
            tracy_ctxs[tracy_ctxs_nof].device_id = device_id;
            tracy_ctxs[tracy_ctxs_nof].tracy_ctx = TracyCLContext( context, device_id );
            tracy_cl_ctx = tracy_ctxs[tracy_ctxs_nof++].tracy_ctx;
        }
    }

    ctx_requested--;

    return tracy_cl_ctx;
}

CL_API_ENTRY cl_int CL_API_CALL clEnqueueCopyBuffer_tracy( cl_command_queue command_queue,
                                                           cl_mem src_buffer,
                                                           cl_mem dst_buffer,
                                                           size_t src_offset,
                                                           size_t dst_offset,
                                                           size_t size,
                                                           cl_uint num_events_in_wait_list,
                                                           const cl_event* event_wait_list,
                                                           cl_event* event )
{
    cl_int err;

    TRACY_CL_WRAP(
        err = tdispatch->clEnqueueCopyBuffer( command_queue, src_buffer, dst_buffer, src_offset, dst_offset, size,
                                              num_events_in_wait_list, event_wait_list, event ); );

    return err;
}

CL_API_ENTRY void* CL_API_CALL clEnqueueMapBuffer_tracy( cl_command_queue command_queue,
                                                         cl_mem buffer,
                                                         cl_bool blocking_map,
                                                         cl_map_flags map_flags,
                                                         size_t offset,
                                                         size_t size,
                                                         cl_uint num_events_in_wait_list,
                                                         const cl_event* event_wait_list,
                                                         cl_event* event,
                                                         cl_int* errcode_ret )
{
    void* mem_region;

    TRACY_CL_WRAP(
        mem_region = tdispatch->clEnqueueMapBuffer( command_queue, buffer, blocking_map, map_flags, offset, size,
                                                    num_events_in_wait_list, event_wait_list, event, errcode_ret ); );

    return mem_region;
}

CL_API_ENTRY cl_int CL_API_CALL clEnqueueReadBuffer_tracy( cl_command_queue command_queue,
                                                           cl_mem buffer,
                                                           cl_bool blocking_read,
                                                           size_t offset,
                                                           size_t size,
                                                           void* ptr,
                                                           cl_uint num_events_in_wait_list,
                                                           const cl_event* event_wait_list,
                                                           cl_event* event )
{
    cl_int err;

    TRACY_CL_WRAP(
        err = tdispatch->clEnqueueReadBuffer( command_queue, buffer, blocking_read, offset, size, ptr,
                                              num_events_in_wait_list, event_wait_list, event ); );

    return err;
}

CL_API_ENTRY cl_int CL_API_CALL clEnqueueWriteBuffer_tracy( cl_command_queue command_queue,
                                                            cl_mem buffer,
                                                            cl_bool blocking_write,
                                                            size_t offset,
                                                            size_t size,
                                                            const void* ptr,
                                                            cl_uint num_events_in_wait_list,
                                                            const cl_event* event_wait_list,
                                                            cl_event* event )
{
    cl_int err;

    TRACY_CL_WRAP(
        err = tdispatch->clEnqueueWriteBuffer( command_queue, buffer, blocking_write, offset, size, ptr,
                                               num_events_in_wait_list, event_wait_list, event ); );

    return err;
}

CL_API_ENTRY cl_int CL_API_CALL clEnqueueUnmapMemObject_tracy( cl_command_queue command_queue,
                                                               cl_mem memobj,
                                                               void* mapped_ptr,
                                                               cl_uint num_events_in_wait_list,
                                                               const cl_event* event_wait_list,
                                                               cl_event* event )
{
    cl_int err;

    TRACY_CL_WRAP(
        err = tdispatch->clEnqueueUnmapMemObject( command_queue, memobj, mapped_ptr, num_events_in_wait_list,
                                                  event_wait_list, event ); );

    return err;
}

CL_API_ENTRY cl_int CL_API_CALL clEnqueueMigrateMemObjects_tracy( cl_command_queue command_queue,
                                                                  cl_uint num_mem_objects,
                                                                  const cl_mem* mem_objects,
                                                                  cl_mem_migration_flags flags,
                                                                  cl_uint num_events_in_wait_list,
                                                                  const cl_event* event_wait_list,
                                                                  cl_event* event )
{
    cl_int err;

    TRACY_CL_WRAP( err = tdispatch->clEnqueueMigrateMemObjects( command_queue, num_mem_objects, mem_objects, flags, num_events_in_wait_list, event_wait_list, event ); );

    return err;
}

CL_API_ENTRY cl_int CL_API_CALL clEnqueueNDRangeKernel_tracy( cl_command_queue command_queue, cl_kernel kernel,
                                                              cl_uint work_dim, const size_t* global_work_offset,
                                                              const size_t* global_work_size,
                                                              const size_t* local_work_size,
                                                              cl_uint num_events_in_wait_list,
                                                              const cl_event* event_wait_list, cl_event* event )
{
    cl_int err;

    TRACY_CL_WRAP(
        err = tdispatch->clEnqueueNDRangeKernel( command_queue, kernel, work_dim, global_work_offset, global_work_size,
                                                 local_work_size, num_events_in_wait_list, event_wait_list, event ); );

    return err;
}

CL_API_ENTRY cl_int CL_API_CALL clEnqueueNativeKernel_tracy( cl_command_queue command_queue,
                                                             void( CL_CALLBACK* user_func )( void* ),
                                                             void* args,
                                                             size_t cb_args,
                                                             cl_uint num_mem_objects,
                                                             const cl_mem* mem_list,
                                                             const void** args_mem_loc,
                                                             cl_uint num_events_in_wait_list,
                                                             const cl_event* event_wait_list,
                                                             cl_event* event )
{
    cl_int err;

    TRACY_CL_WRAP( err = tdispatch->clEnqueueNativeKernel( command_queue, user_func, args, cb_args, num_mem_objects,
                                                           mem_list, args_mem_loc, num_events_in_wait_list,
                                                           event_wait_list, event ); );

    return err;
}

CL_API_ENTRY cl_int CL_API_CALL clBuildProgram_tracy( cl_program program,
                                                      cl_uint num_devices,
                                                      const cl_device_id* device_list,
                                                      const char* options,
                                                      void( CL_CALLBACK* pfn_notify )( cl_program program, void* user_data ),
                                                      void* user_data )
{
    cl_int err;

    ZoneScopedCS( tracy::Color::CadetBlue, 4 );
    err = tdispatch->clBuildProgram( program, num_devices, device_list, options, pfn_notify, user_data );

    return err;
}

CL_API_ENTRY cl_int CL_API_CALL clFinish_tracy( cl_command_queue command_queue )
{
    cl_int err;

    ZoneScopedCS( tracy::Color::CadetBlue, 4 );

    err = tdispatch->clFinish( command_queue );

    TracyCLCtx _tracy_cl_ctx = get_tracy_cl_ctx( command_queue );
    if( _tracy_cl_ctx != nullptr )
        TracyCLCollect( _tracy_cl_ctx );

    return err;
}
}

CL_API_ENTRY cl_int CL_API_CALL clGetLayerInfo( cl_layer_info param_name, size_t param_value_size, void* param_value,
                                                size_t* param_value_size_ret )
{
    switch( param_name )
    {
    case CL_LAYER_API_VERSION:
        if( param_value )
        {
            if( param_value_size < sizeof( cl_layer_api_version ) ) return CL_INVALID_VALUE;

            *( (cl_layer_api_version*)param_value ) = CL_LAYER_API_VERSION_100;
        }
        if( param_value_size_ret ) *param_value_size_ret = sizeof( cl_layer_api_version );
        break;
    default:
        return CL_INVALID_VALUE;
    }
    return CL_SUCCESS;
}

CL_API_ENTRY cl_int CL_API_CALL clInitLayer( cl_uint num_entries, const struct _cl_icd_dispatch* target_dispatch,
                                             cl_uint* num_entries_ret,
                                             const struct _cl_icd_dispatch** layer_dispatch_ret )
{
    if( target_dispatch == nullptr || num_entries_ret == nullptr || layer_dispatch_ret == nullptr )
        return CL_INVALID_VALUE;

    /* Check that the loader does not provide us with a dispatch table
     * smaller than the one we've been compiled with. */
    if( num_entries < ( sizeof( dispatch ) / sizeof( dispatch.clFinish ) ) ) return CL_INVALID_VALUE;

    tdispatch = target_dispatch;

    /* Buffer Objects */
    dispatch.clEnqueueCopyBuffer = &clEnqueueCopyBuffer_tracy;
    dispatch.clEnqueueMapBuffer = &clEnqueueMapBuffer_tracy;
    dispatch.clEnqueueReadBuffer = &clEnqueueReadBuffer_tracy;
    dispatch.clEnqueueWriteBuffer = &clEnqueueWriteBuffer_tracy;

    /* Memory Objects */
    dispatch.clEnqueueUnmapMemObject = &clEnqueueUnmapMemObject_tracy;
    dispatch.clEnqueueMigrateMemObjects = &clEnqueueMigrateMemObjects_tracy;

    /* Executing Kernels */
    dispatch.clEnqueueNDRangeKernel = &clEnqueueNDRangeKernel_tracy;
    dispatch.clEnqueueNativeKernel = &clEnqueueNativeKernel_tracy;

    /* Program Objects */
    dispatch.clBuildProgram = &clBuildProgram_tracy;

    /* Collecting event information */
    dispatch.clFinish = &clFinish_tracy;

    *layer_dispatch_ret = &dispatch;
    *num_entries_ret = sizeof( dispatch ) / sizeof( dispatch.clFinish );

    TracyMessageL( "Tracy OpenCL Layer loaded!" );

    return CL_SUCCESS;
}
