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

#include <cstdio>

#include <CL/cl_layer.h>

#include <tracy/tracy/TracyOpenCL.hpp>

struct context_device_ctx
{
    cl_context context;
    cl_device_id device_id;
    TracyCLCtx tracy_ctx;
};

static struct _cl_icd_dispatch dispatch;
static const struct _cl_icd_dispatch* tdispatch;

static struct context_device_ctx tracy_ctxs[32];
static int tracy_ctxs_nof = 0;

static TracyCLCtx get_tracy_cl_ctx( cl_command_queue command_queue )
{
    cl_context context;
    cl_device_id device_id;
    cl_int err;

    // Check if there is a TracyCLCtx for this combination of cl_context and cl_device_id.
    err = tdispatch->clGetCommandQueueInfo( command_queue, CL_QUEUE_CONTEXT, sizeof( cl_context ), (void*)&context,
                                            nullptr );
    if( err != CL_SUCCESS ) return nullptr;

    err = tdispatch->clGetCommandQueueInfo( command_queue, CL_QUEUE_DEVICE, sizeof( cl_device_id ), (void*)&device_id,
                                            nullptr );
    if( err != CL_SUCCESS ) return nullptr;

    for( int i = 0; i < tracy_ctxs_nof; i++ )
    {
        if( context == tracy_ctxs[i].context && device_id == tracy_ctxs[i].device_id ) return tracy_ctxs[i].tracy_ctx;
    }

    // Create a new TracyCLCtx.
    tracy_ctxs[tracy_ctxs_nof].context = context;
    tracy_ctxs[tracy_ctxs_nof].device_id = device_id;
    tracy_ctxs[tracy_ctxs_nof].tracy_ctx = TracyCLContext( context, device_id );

    return tracy_ctxs[tracy_ctxs_nof++].tracy_ctx;
}

static CL_API_ENTRY cl_int CL_API_CALL clEnqueueNDRangeKernel_tracy( cl_command_queue command_queue, cl_kernel kernel,
                                                                     cl_uint work_dim, const size_t* global_work_offset,
                                                                     const size_t* global_work_size,
                                                                     const size_t* local_work_size,
                                                                     cl_uint num_events_in_wait_list,
                                                                     const cl_event* event_wait_list, cl_event* event )
{
    cl_event tracy_event;
    cl_int err;

    TracyCLZone( get_tracy_cl_ctx( command_queue ), __func__ );

    if( event == nullptr )
    {
        err = tdispatch->clEnqueueNDRangeKernel( command_queue, kernel, work_dim, global_work_offset, global_work_size,
                                                 local_work_size, num_events_in_wait_list, event_wait_list,
                                                 &tracy_event );

        TracyCLZoneSetEvent( tracy_event );
    }
    else
    {
        err = tdispatch->clEnqueueNDRangeKernel( command_queue, kernel, work_dim, global_work_offset, global_work_size,
                                                 local_work_size, num_events_in_wait_list, event_wait_list, event );

        TracyCLZoneSetEvent( *event );
    }

    return err;
}

static CL_API_ENTRY cl_int CL_API_CALL clFinish_tracy( cl_command_queue command_queue )
{
    cl_int err = tdispatch->clFinish( command_queue );
    TracyCLCollect( get_tracy_cl_ctx( command_queue ) );

    return err;
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
                                             cl_uint* num_entries_out,
                                             const struct _cl_icd_dispatch** layer_dispatch_ret )
{
    if( target_dispatch == nullptr || num_entries_out == nullptr || layer_dispatch_ret == nullptr )
        return CL_INVALID_VALUE;

    /* Check that the loader does not provide us with a dispatch table
     * smaller than the one we've been compiled with. */
    if( num_entries < ( sizeof( dispatch ) / sizeof( dispatch.clFinish ) ) ) return CL_INVALID_VALUE;

    tdispatch = target_dispatch;
    tracy_ctxs_nof = 0;

    dispatch.clEnqueueNDRangeKernel = &clEnqueueNDRangeKernel_tracy;
    dispatch.clFinish = &clFinish_tracy;

    *layer_dispatch_ret = &dispatch;
    *num_entries_out = sizeof( dispatch ) / sizeof( dispatch.clFinish );

    TracyMessageL( "Tracy OpenCL Layer loaded!" );

    return CL_SUCCESS;
}
