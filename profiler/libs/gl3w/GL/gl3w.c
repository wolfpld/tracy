/*
 * This file was generated with gl3w_gen.py, part of gl3w
 * (hosted at https://github.com/skaslev/gl3w)
 *
 * This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * In jurisdictions that recognize copyright laws, the author or authors
 * of this software dedicate any and all copyright interest in the
 * software to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and
 * successors. We intend this dedication to be an overt act of
 * relinquishment in perpetuity of all present and future rights to this
 * software under copyright law.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <GL/gl3w.h>
#include <stdlib.h>

#define ARRAY_SIZE(x)  (sizeof(x) / sizeof((x)[0]))

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1 // Exclude advanced Windows headers
#endif // WIN32_LEAN_AND_MEAN
#include <windows.h>

static HMODULE libgl;
typedef PROC(__stdcall* GL3WglGetProcAddr)(LPCSTR);
static GL3WglGetProcAddr wgl_get_proc_address;

static int open_libgl(void)
{
	libgl = LoadLibraryA("opengl32.dll");
	if (!libgl)
		return GL3W_ERROR_LIBRARY_OPEN;

	wgl_get_proc_address = (GL3WglGetProcAddr)GetProcAddress(libgl, "wglGetProcAddress");
	return GL3W_OK;
}

static void close_libgl(void)
{
	FreeLibrary(libgl);
}

static GL3WglProc get_proc(const char *proc)
{
	GL3WglProc res;

	res = (GL3WglProc)wgl_get_proc_address(proc);
	if (!res)
		res = (GL3WglProc)GetProcAddress(libgl, proc);
	return res;
}
#elif defined(__APPLE__)
#include <dlfcn.h>

static void *libgl;

static int open_libgl(void)
{
	libgl = dlopen("/System/Library/Frameworks/OpenGL.framework/OpenGL", RTLD_LAZY | RTLD_LOCAL);
	if (!libgl)
		return GL3W_ERROR_LIBRARY_OPEN;

	return GL3W_OK;
}

static void close_libgl(void)
{
	dlclose(libgl);
}

static GL3WglProc get_proc(const char *proc)
{
	GL3WglProc res;

	*(void **)(&res) = dlsym(libgl, proc);
	return res;
}
#else
#include <dlfcn.h>

static void *libgl;
static GL3WglProc (*glx_get_proc_address)(const GLubyte *);

static int open_libgl(void)
{
	libgl = dlopen("libGL.so.1", RTLD_LAZY | RTLD_LOCAL);
	if (!libgl)
		return GL3W_ERROR_LIBRARY_OPEN;

	*(void **)(&glx_get_proc_address) = dlsym(libgl, "glXGetProcAddressARB");
	return GL3W_OK;
}

static void close_libgl(void)
{
	dlclose(libgl);
}

static GL3WglProc get_proc(const char *proc)
{
	GL3WglProc res;

	res = glx_get_proc_address((const GLubyte *)proc);
	if (!res)
		*(void **)(&res) = dlsym(libgl, proc);
	return res;
}
#endif

static struct {
	int major, minor;
} version;

static int parse_version(void)
{
	if (!glGetIntegerv)
		return GL3W_ERROR_INIT;

	glGetIntegerv(GL_MAJOR_VERSION, &version.major);
	glGetIntegerv(GL_MINOR_VERSION, &version.minor);

	if (version.major < 3)
		return GL3W_ERROR_OPENGL_VERSION;
	return GL3W_OK;
}

static void load_procs(GL3WGetProcAddressProc proc);

int gl3wInit(void)
{
	int res;

	res = open_libgl();
	if (res)
		return res;

	atexit(close_libgl);
	return gl3wInit2(get_proc);
}

int gl3wInit2(GL3WGetProcAddressProc proc)
{
	load_procs(proc);
	return parse_version();
}

int gl3wIsSupported(int major, int minor)
{
	if (major < 3)
		return 0;
	if (version.major == major)
		return version.minor >= minor;
	return version.major >= major;
}

GL3WglProc gl3wGetProcAddress(const char *proc)
{
	return get_proc(proc);
}

static const char *proc_names[] = {
	"glActiveShaderProgram",
	"glActiveTexture",
	"glAttachShader",
	"glBeginConditionalRender",
	"glBeginQuery",
	"glBeginQueryIndexed",
	"glBeginTransformFeedback",
	"glBindAttribLocation",
	"glBindBuffer",
	"glBindBufferBase",
	"glBindBufferRange",
	"glBindBuffersBase",
	"glBindBuffersRange",
	"glBindFragDataLocation",
	"glBindFragDataLocationIndexed",
	"glBindFramebuffer",
	"glBindImageTexture",
	"glBindImageTextures",
	"glBindProgramPipeline",
	"glBindRenderbuffer",
	"glBindSampler",
	"glBindSamplers",
	"glBindTexture",
	"glBindTextureUnit",
	"glBindTextures",
	"glBindTransformFeedback",
	"glBindVertexArray",
	"glBindVertexBuffer",
	"glBindVertexBuffers",
	"glBlendColor",
	"glBlendEquation",
	"glBlendEquationSeparate",
	"glBlendEquationSeparatei",
	"glBlendEquationi",
	"glBlendFunc",
	"glBlendFuncSeparate",
	"glBlendFuncSeparatei",
	"glBlendFunci",
	"glBlitFramebuffer",
	"glBlitNamedFramebuffer",
	"glBufferData",
	"glBufferStorage",
	"glBufferSubData",
	"glCheckFramebufferStatus",
	"glCheckNamedFramebufferStatus",
	"glClampColor",
	"glClear",
	"glClearBufferData",
	"glClearBufferSubData",
	"glClearBufferfi",
	"glClearBufferfv",
	"glClearBufferiv",
	"glClearBufferuiv",
	"glClearColor",
	"glClearDepth",
	"glClearDepthf",
	"glClearNamedBufferData",
	"glClearNamedBufferSubData",
	"glClearNamedFramebufferfi",
	"glClearNamedFramebufferfv",
	"glClearNamedFramebufferiv",
	"glClearNamedFramebufferuiv",
	"glClearStencil",
	"glClearTexImage",
	"glClearTexSubImage",
	"glClientWaitSync",
	"glClipControl",
	"glColorMask",
	"glColorMaski",
	"glCompileShader",
	"glCompressedTexImage1D",
	"glCompressedTexImage2D",
	"glCompressedTexImage3D",
	"glCompressedTexSubImage1D",
	"glCompressedTexSubImage2D",
	"glCompressedTexSubImage3D",
	"glCompressedTextureSubImage1D",
	"glCompressedTextureSubImage2D",
	"glCompressedTextureSubImage3D",
	"glCopyBufferSubData",
	"glCopyImageSubData",
	"glCopyNamedBufferSubData",
	"glCopyTexImage1D",
	"glCopyTexImage2D",
	"glCopyTexSubImage1D",
	"glCopyTexSubImage2D",
	"glCopyTexSubImage3D",
	"glCopyTextureSubImage1D",
	"glCopyTextureSubImage2D",
	"glCopyTextureSubImage3D",
	"glCreateBuffers",
	"glCreateFramebuffers",
	"glCreateProgram",
	"glCreateProgramPipelines",
	"glCreateQueries",
	"glCreateRenderbuffers",
	"glCreateSamplers",
	"glCreateShader",
	"glCreateShaderProgramv",
	"glCreateTextures",
	"glCreateTransformFeedbacks",
	"glCreateVertexArrays",
	"glCullFace",
	"glDebugMessageCallback",
	"glDebugMessageControl",
	"glDebugMessageInsert",
	"glDeleteBuffers",
	"glDeleteFramebuffers",
	"glDeleteProgram",
	"glDeleteProgramPipelines",
	"glDeleteQueries",
	"glDeleteRenderbuffers",
	"glDeleteSamplers",
	"glDeleteShader",
	"glDeleteSync",
	"glDeleteTextures",
	"glDeleteTransformFeedbacks",
	"glDeleteVertexArrays",
	"glDepthFunc",
	"glDepthMask",
	"glDepthRange",
	"glDepthRangeArrayv",
	"glDepthRangeIndexed",
	"glDepthRangef",
	"glDetachShader",
	"glDisable",
	"glDisableVertexArrayAttrib",
	"glDisableVertexAttribArray",
	"glDisablei",
	"glDispatchCompute",
	"glDispatchComputeIndirect",
	"glDrawArrays",
	"glDrawArraysIndirect",
	"glDrawArraysInstanced",
	"glDrawArraysInstancedBaseInstance",
	"glDrawBuffer",
	"glDrawBuffers",
	"glDrawElements",
	"glDrawElementsBaseVertex",
	"glDrawElementsIndirect",
	"glDrawElementsInstanced",
	"glDrawElementsInstancedBaseInstance",
	"glDrawElementsInstancedBaseVertex",
	"glDrawElementsInstancedBaseVertexBaseInstance",
	"glDrawRangeElements",
	"glDrawRangeElementsBaseVertex",
	"glDrawTransformFeedback",
	"glDrawTransformFeedbackInstanced",
	"glDrawTransformFeedbackStream",
	"glDrawTransformFeedbackStreamInstanced",
	"glEnable",
	"glEnableVertexArrayAttrib",
	"glEnableVertexAttribArray",
	"glEnablei",
	"glEndConditionalRender",
	"glEndQuery",
	"glEndQueryIndexed",
	"glEndTransformFeedback",
	"glFenceSync",
	"glFinish",
	"glFlush",
	"glFlushMappedBufferRange",
	"glFlushMappedNamedBufferRange",
	"glFramebufferParameteri",
	"glFramebufferParameteriMESA",
	"glFramebufferRenderbuffer",
	"glFramebufferTexture",
	"glFramebufferTexture1D",
	"glFramebufferTexture2D",
	"glFramebufferTexture3D",
	"glFramebufferTextureLayer",
	"glFrontFace",
	"glGenBuffers",
	"glGenFramebuffers",
	"glGenProgramPipelines",
	"glGenQueries",
	"glGenRenderbuffers",
	"glGenSamplers",
	"glGenTextures",
	"glGenTransformFeedbacks",
	"glGenVertexArrays",
	"glGenerateMipmap",
	"glGenerateTextureMipmap",
	"glGetActiveAtomicCounterBufferiv",
	"glGetActiveAttrib",
	"glGetActiveSubroutineName",
	"glGetActiveSubroutineUniformName",
	"glGetActiveSubroutineUniformiv",
	"glGetActiveUniform",
	"glGetActiveUniformBlockName",
	"glGetActiveUniformBlockiv",
	"glGetActiveUniformName",
	"glGetActiveUniformsiv",
	"glGetAttachedShaders",
	"glGetAttribLocation",
	"glGetBooleani_v",
	"glGetBooleanv",
	"glGetBufferParameteri64v",
	"glGetBufferParameteriv",
	"glGetBufferPointerv",
	"glGetBufferSubData",
	"glGetCompressedTexImage",
	"glGetCompressedTextureImage",
	"glGetCompressedTextureSubImage",
	"glGetDebugMessageLog",
	"glGetDoublei_v",
	"glGetDoublev",
	"glGetError",
	"glGetFloati_v",
	"glGetFloatv",
	"glGetFragDataIndex",
	"glGetFragDataLocation",
	"glGetFramebufferAttachmentParameteriv",
	"glGetFramebufferParameteriv",
	"glGetFramebufferParameterivMESA",
	"glGetGraphicsResetStatus",
	"glGetInteger64i_v",
	"glGetInteger64v",
	"glGetIntegeri_v",
	"glGetIntegerv",
	"glGetInternalformati64v",
	"glGetInternalformativ",
	"glGetMultisamplefv",
	"glGetNamedBufferParameteri64v",
	"glGetNamedBufferParameteriv",
	"glGetNamedBufferPointerv",
	"glGetNamedBufferSubData",
	"glGetNamedFramebufferAttachmentParameteriv",
	"glGetNamedFramebufferParameteriv",
	"glGetNamedRenderbufferParameteriv",
	"glGetObjectLabel",
	"glGetObjectPtrLabel",
	"glGetPointerv",
	"glGetProgramBinary",
	"glGetProgramInfoLog",
	"glGetProgramInterfaceiv",
	"glGetProgramPipelineInfoLog",
	"glGetProgramPipelineiv",
	"glGetProgramResourceIndex",
	"glGetProgramResourceLocation",
	"glGetProgramResourceLocationIndex",
	"glGetProgramResourceName",
	"glGetProgramResourceiv",
	"glGetProgramStageiv",
	"glGetProgramiv",
	"glGetQueryBufferObjecti64v",
	"glGetQueryBufferObjectiv",
	"glGetQueryBufferObjectui64v",
	"glGetQueryBufferObjectuiv",
	"glGetQueryIndexediv",
	"glGetQueryObjecti64v",
	"glGetQueryObjectiv",
	"glGetQueryObjectui64v",
	"glGetQueryObjectuiv",
	"glGetQueryiv",
	"glGetRenderbufferParameteriv",
	"glGetSamplerParameterIiv",
	"glGetSamplerParameterIuiv",
	"glGetSamplerParameterfv",
	"glGetSamplerParameteriv",
	"glGetShaderInfoLog",
	"glGetShaderPrecisionFormat",
	"glGetShaderSource",
	"glGetShaderiv",
	"glGetString",
	"glGetStringi",
	"glGetSubroutineIndex",
	"glGetSubroutineUniformLocation",
	"glGetSynciv",
	"glGetTexImage",
	"glGetTexLevelParameterfv",
	"glGetTexLevelParameteriv",
	"glGetTexParameterIiv",
	"glGetTexParameterIuiv",
	"glGetTexParameterfv",
	"glGetTexParameteriv",
	"glGetTextureImage",
	"glGetTextureLevelParameterfv",
	"glGetTextureLevelParameteriv",
	"glGetTextureParameterIiv",
	"glGetTextureParameterIuiv",
	"glGetTextureParameterfv",
	"glGetTextureParameteriv",
	"glGetTextureSubImage",
	"glGetTransformFeedbackVarying",
	"glGetTransformFeedbacki64_v",
	"glGetTransformFeedbacki_v",
	"glGetTransformFeedbackiv",
	"glGetUniformBlockIndex",
	"glGetUniformIndices",
	"glGetUniformLocation",
	"glGetUniformSubroutineuiv",
	"glGetUniformdv",
	"glGetUniformfv",
	"glGetUniformiv",
	"glGetUniformuiv",
	"glGetVertexArrayIndexed64iv",
	"glGetVertexArrayIndexediv",
	"glGetVertexArrayiv",
	"glGetVertexAttribIiv",
	"glGetVertexAttribIuiv",
	"glGetVertexAttribLdv",
	"glGetVertexAttribPointerv",
	"glGetVertexAttribdv",
	"glGetVertexAttribfv",
	"glGetVertexAttribiv",
	"glGetnCompressedTexImage",
	"glGetnTexImage",
	"glGetnUniformdv",
	"glGetnUniformfv",
	"glGetnUniformiv",
	"glGetnUniformuiv",
	"glHint",
	"glInvalidateBufferData",
	"glInvalidateBufferSubData",
	"glInvalidateFramebuffer",
	"glInvalidateNamedFramebufferData",
	"glInvalidateNamedFramebufferSubData",
	"glInvalidateSubFramebuffer",
	"glInvalidateTexImage",
	"glInvalidateTexSubImage",
	"glIsBuffer",
	"glIsEnabled",
	"glIsEnabledi",
	"glIsFramebuffer",
	"glIsProgram",
	"glIsProgramPipeline",
	"glIsQuery",
	"glIsRenderbuffer",
	"glIsSampler",
	"glIsShader",
	"glIsSync",
	"glIsTexture",
	"glIsTransformFeedback",
	"glIsVertexArray",
	"glLineWidth",
	"glLinkProgram",
	"glLogicOp",
	"glMapBuffer",
	"glMapBufferRange",
	"glMapNamedBuffer",
	"glMapNamedBufferRange",
	"glMemoryBarrier",
	"glMemoryBarrierByRegion",
	"glMinSampleShading",
	"glMultiDrawArrays",
	"glMultiDrawArraysIndirect",
	"glMultiDrawArraysIndirectCount",
	"glMultiDrawElements",
	"glMultiDrawElementsBaseVertex",
	"glMultiDrawElementsIndirect",
	"glMultiDrawElementsIndirectCount",
	"glNamedBufferData",
	"glNamedBufferStorage",
	"glNamedBufferSubData",
	"glNamedFramebufferDrawBuffer",
	"glNamedFramebufferDrawBuffers",
	"glNamedFramebufferParameteri",
	"glNamedFramebufferReadBuffer",
	"glNamedFramebufferRenderbuffer",
	"glNamedFramebufferTexture",
	"glNamedFramebufferTextureLayer",
	"glNamedRenderbufferStorage",
	"glNamedRenderbufferStorageMultisample",
	"glObjectLabel",
	"glObjectPtrLabel",
	"glPatchParameterfv",
	"glPatchParameteri",
	"glPauseTransformFeedback",
	"glPixelStoref",
	"glPixelStorei",
	"glPointParameterf",
	"glPointParameterfv",
	"glPointParameteri",
	"glPointParameteriv",
	"glPointSize",
	"glPolygonMode",
	"glPolygonOffset",
	"glPolygonOffsetClamp",
	"glPopDebugGroup",
	"glPrimitiveRestartIndex",
	"glProgramBinary",
	"glProgramParameteri",
	"glProgramUniform1d",
	"glProgramUniform1dv",
	"glProgramUniform1f",
	"glProgramUniform1fv",
	"glProgramUniform1i",
	"glProgramUniform1iv",
	"glProgramUniform1ui",
	"glProgramUniform1uiv",
	"glProgramUniform2d",
	"glProgramUniform2dv",
	"glProgramUniform2f",
	"glProgramUniform2fv",
	"glProgramUniform2i",
	"glProgramUniform2iv",
	"glProgramUniform2ui",
	"glProgramUniform2uiv",
	"glProgramUniform3d",
	"glProgramUniform3dv",
	"glProgramUniform3f",
	"glProgramUniform3fv",
	"glProgramUniform3i",
	"glProgramUniform3iv",
	"glProgramUniform3ui",
	"glProgramUniform3uiv",
	"glProgramUniform4d",
	"glProgramUniform4dv",
	"glProgramUniform4f",
	"glProgramUniform4fv",
	"glProgramUniform4i",
	"glProgramUniform4iv",
	"glProgramUniform4ui",
	"glProgramUniform4uiv",
	"glProgramUniformMatrix2dv",
	"glProgramUniformMatrix2fv",
	"glProgramUniformMatrix2x3dv",
	"glProgramUniformMatrix2x3fv",
	"glProgramUniformMatrix2x4dv",
	"glProgramUniformMatrix2x4fv",
	"glProgramUniformMatrix3dv",
	"glProgramUniformMatrix3fv",
	"glProgramUniformMatrix3x2dv",
	"glProgramUniformMatrix3x2fv",
	"glProgramUniformMatrix3x4dv",
	"glProgramUniformMatrix3x4fv",
	"glProgramUniformMatrix4dv",
	"glProgramUniformMatrix4fv",
	"glProgramUniformMatrix4x2dv",
	"glProgramUniformMatrix4x2fv",
	"glProgramUniformMatrix4x3dv",
	"glProgramUniformMatrix4x3fv",
	"glProvokingVertex",
	"glPushDebugGroup",
	"glQueryCounter",
	"glReadBuffer",
	"glReadPixels",
	"glReadnPixels",
	"glReleaseShaderCompiler",
	"glRenderbufferStorage",
	"glRenderbufferStorageMultisample",
	"glResumeTransformFeedback",
	"glSampleCoverage",
	"glSampleMaski",
	"glSamplerParameterIiv",
	"glSamplerParameterIuiv",
	"glSamplerParameterf",
	"glSamplerParameterfv",
	"glSamplerParameteri",
	"glSamplerParameteriv",
	"glScissor",
	"glScissorArrayv",
	"glScissorIndexed",
	"glScissorIndexedv",
	"glShaderBinary",
	"glShaderSource",
	"glShaderStorageBlockBinding",
	"glSpecializeShader",
	"glStencilFunc",
	"glStencilFuncSeparate",
	"glStencilMask",
	"glStencilMaskSeparate",
	"glStencilOp",
	"glStencilOpSeparate",
	"glTexBuffer",
	"glTexBufferRange",
	"glTexImage1D",
	"glTexImage2D",
	"glTexImage2DMultisample",
	"glTexImage3D",
	"glTexImage3DMultisample",
	"glTexParameterIiv",
	"glTexParameterIuiv",
	"glTexParameterf",
	"glTexParameterfv",
	"glTexParameteri",
	"glTexParameteriv",
	"glTexStorage1D",
	"glTexStorage2D",
	"glTexStorage2DMultisample",
	"glTexStorage3D",
	"glTexStorage3DMultisample",
	"glTexSubImage1D",
	"glTexSubImage2D",
	"glTexSubImage3D",
	"glTextureBarrier",
	"glTextureBuffer",
	"glTextureBufferRange",
	"glTextureParameterIiv",
	"glTextureParameterIuiv",
	"glTextureParameterf",
	"glTextureParameterfv",
	"glTextureParameteri",
	"glTextureParameteriv",
	"glTextureStorage1D",
	"glTextureStorage2D",
	"glTextureStorage2DMultisample",
	"glTextureStorage3D",
	"glTextureStorage3DMultisample",
	"glTextureSubImage1D",
	"glTextureSubImage2D",
	"glTextureSubImage3D",
	"glTextureView",
	"glTransformFeedbackBufferBase",
	"glTransformFeedbackBufferRange",
	"glTransformFeedbackVaryings",
	"glUniform1d",
	"glUniform1dv",
	"glUniform1f",
	"glUniform1fv",
	"glUniform1i",
	"glUniform1iv",
	"glUniform1ui",
	"glUniform1uiv",
	"glUniform2d",
	"glUniform2dv",
	"glUniform2f",
	"glUniform2fv",
	"glUniform2i",
	"glUniform2iv",
	"glUniform2ui",
	"glUniform2uiv",
	"glUniform3d",
	"glUniform3dv",
	"glUniform3f",
	"glUniform3fv",
	"glUniform3i",
	"glUniform3iv",
	"glUniform3ui",
	"glUniform3uiv",
	"glUniform4d",
	"glUniform4dv",
	"glUniform4f",
	"glUniform4fv",
	"glUniform4i",
	"glUniform4iv",
	"glUniform4ui",
	"glUniform4uiv",
	"glUniformBlockBinding",
	"glUniformMatrix2dv",
	"glUniformMatrix2fv",
	"glUniformMatrix2x3dv",
	"glUniformMatrix2x3fv",
	"glUniformMatrix2x4dv",
	"glUniformMatrix2x4fv",
	"glUniformMatrix3dv",
	"glUniformMatrix3fv",
	"glUniformMatrix3x2dv",
	"glUniformMatrix3x2fv",
	"glUniformMatrix3x4dv",
	"glUniformMatrix3x4fv",
	"glUniformMatrix4dv",
	"glUniformMatrix4fv",
	"glUniformMatrix4x2dv",
	"glUniformMatrix4x2fv",
	"glUniformMatrix4x3dv",
	"glUniformMatrix4x3fv",
	"glUniformSubroutinesuiv",
	"glUnmapBuffer",
	"glUnmapNamedBuffer",
	"glUseProgram",
	"glUseProgramStages",
	"glValidateProgram",
	"glValidateProgramPipeline",
	"glVertexArrayAttribBinding",
	"glVertexArrayAttribFormat",
	"glVertexArrayAttribIFormat",
	"glVertexArrayAttribLFormat",
	"glVertexArrayBindingDivisor",
	"glVertexArrayElementBuffer",
	"glVertexArrayVertexBuffer",
	"glVertexArrayVertexBuffers",
	"glVertexAttrib1d",
	"glVertexAttrib1dv",
	"glVertexAttrib1f",
	"glVertexAttrib1fv",
	"glVertexAttrib1s",
	"glVertexAttrib1sv",
	"glVertexAttrib2d",
	"glVertexAttrib2dv",
	"glVertexAttrib2f",
	"glVertexAttrib2fv",
	"glVertexAttrib2s",
	"glVertexAttrib2sv",
	"glVertexAttrib3d",
	"glVertexAttrib3dv",
	"glVertexAttrib3f",
	"glVertexAttrib3fv",
	"glVertexAttrib3s",
	"glVertexAttrib3sv",
	"glVertexAttrib4Nbv",
	"glVertexAttrib4Niv",
	"glVertexAttrib4Nsv",
	"glVertexAttrib4Nub",
	"glVertexAttrib4Nubv",
	"glVertexAttrib4Nuiv",
	"glVertexAttrib4Nusv",
	"glVertexAttrib4bv",
	"glVertexAttrib4d",
	"glVertexAttrib4dv",
	"glVertexAttrib4f",
	"glVertexAttrib4fv",
	"glVertexAttrib4iv",
	"glVertexAttrib4s",
	"glVertexAttrib4sv",
	"glVertexAttrib4ubv",
	"glVertexAttrib4uiv",
	"glVertexAttrib4usv",
	"glVertexAttribBinding",
	"glVertexAttribDivisor",
	"glVertexAttribFormat",
	"glVertexAttribI1i",
	"glVertexAttribI1iv",
	"glVertexAttribI1ui",
	"glVertexAttribI1uiv",
	"glVertexAttribI2i",
	"glVertexAttribI2iv",
	"glVertexAttribI2ui",
	"glVertexAttribI2uiv",
	"glVertexAttribI3i",
	"glVertexAttribI3iv",
	"glVertexAttribI3ui",
	"glVertexAttribI3uiv",
	"glVertexAttribI4bv",
	"glVertexAttribI4i",
	"glVertexAttribI4iv",
	"glVertexAttribI4sv",
	"glVertexAttribI4ubv",
	"glVertexAttribI4ui",
	"glVertexAttribI4uiv",
	"glVertexAttribI4usv",
	"glVertexAttribIFormat",
	"glVertexAttribIPointer",
	"glVertexAttribL1d",
	"glVertexAttribL1dv",
	"glVertexAttribL2d",
	"glVertexAttribL2dv",
	"glVertexAttribL3d",
	"glVertexAttribL3dv",
	"glVertexAttribL4d",
	"glVertexAttribL4dv",
	"glVertexAttribLFormat",
	"glVertexAttribLPointer",
	"glVertexAttribP1ui",
	"glVertexAttribP1uiv",
	"glVertexAttribP2ui",
	"glVertexAttribP2uiv",
	"glVertexAttribP3ui",
	"glVertexAttribP3uiv",
	"glVertexAttribP4ui",
	"glVertexAttribP4uiv",
	"glVertexAttribPointer",
	"glVertexBindingDivisor",
	"glViewport",
	"glViewportArrayv",
	"glViewportIndexedf",
	"glViewportIndexedfv",
	"glWaitSync",
};

union GL3WProcs gl3wProcs;

static void load_procs(GL3WGetProcAddressProc proc)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(proc_names); i++)
		gl3wProcs.ptr[i] = proc(proc_names[i]);
}
