/*
*******************************************************************************
*= = 文件名称：ProtectProcess.h
*= = 文件描述：关于ProtectProcess的头文件
*= = 作    者：indigo
*= = 编写时间：2016-07-09 19:18:00
*******************************************************************************
*/

#ifndef __PROTECTPROCESS_H__
#define __PROTECTPROCESS_H__

//*============================================================================ 
//*= = 头文件声明 
//*============================================================================ 

#include <ntifs.h>
#include <windef.h>
#include "ntddk.h"

#pragma comment (lib,"ksecdd.lib")

//*============================================================================ 
//*= = 宏与结构体 
//*============================================================================ 

#define DEVICE_NAME			L"\\Device\\ProcessGuard"
#define SYMBOL_NAME			L"\\??\\ProcessGuard"
#define DRIVER_NAME			L"\\Driver\\ProcessGuard"
#define MAX_PROCESS			1000
//定义控制码
#define PROTECTBYPID		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_IN_DIRECT, FILE_ANY_ACCESS)
#define UNPROTECTBYPID		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_IN_DIRECT, FILE_ANY_ACCESS)
#define KILLBYPID			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_IN_DIRECT, FILE_ANY_ACCESS)

//对权限的定义
#define PROCESS_TERMINATE         (0x0001)  // winnt
#define PROCESS_CREATE_THREAD     (0x0002)  // winnt
#define PROCESS_SET_SESSIONID     (0x0004)  // winnt
#define PROCESS_VM_OPERATION      (0x0008)  // winnt
#define PROCESS_VM_READ           (0x0010)  // winnt
#define PROCESS_VM_WRITE          (0x0020)  // winnt
#define PS_PROCESS_FLAGS_PROCESS_DELETE         0x00000008UL

//声明函数指针类型
typedef CCHAR(*GETPREVIOUSMODE)();

typedef PETHREAD(*PSGETNEXTPROCESSTHREAD) (PETHREAD Thread);

typedef NTSTATUS(*OBREFERENCEOBJECTBYNAME)(
	__in PUNICODE_STRING ObjectName,
	__in ULONG Attributes,
	__in_opt PACCESS_STATE AccessState,
	__in_opt ACCESS_MASK DesiredAccess,
	__in POBJECT_TYPE ObjectType,
	__in KPROCESSOR_MODE AccessMode,
	__inout_opt PVOID ParseContext,
	__out PVOID *Object
	);

extern POBJECT_TYPE *IoDriverObjectType;


//定义通用节点
typedef struct _LISTNODE {
	struct _LISTNODE* next;
	ULONG data;
} LISTNODE, *PLISTNODE;

//定义进程信息
typedef struct _PROCESSINFO {
	ULONG ProcessId;
	WCHAR Name[MAX_PATH];
} PROCESSINFO, *PPROCESSINFO;

//定义保护进程节点
typedef struct _PROTECTINFO
{
	ULONG ProcessId;
	PLISTNODE AllowedUser;
} PROTECTINFO, *PPROTECTINFO;

#pragma pack(1)
typedef struct _SERVICEDESCRIPTORTABLE{
	PULONG ServiceTableBase;
	PULONG ServiceCounterTableBase;
	ULONG  NumberOfServices;
	PULONG ParmTableBase;
} SERVICEDESCRIPTORTABLE, *PSERVICEDESCRIPTORTABLE;
#pragma pack()

__declspec(dllimport) SERVICEDESCRIPTORTABLE KeServiceDescriptorTable;

//隐藏链表和进程保护链表
PLISTNODE ProtectList = NULL;

//win7 32位下的各种偏移
ULONG g_ProcessIdOffset = 0xb4;					//进程ID偏移
ULONG g_ProcessNameOffset = 0x16c;				//进程名指针偏移
ULONG g_ProcessListOffset = 0xb8;				//进程链表指针偏移
ULONG g_ProcessFlagsOffset = 0x270;				//进程标识偏移
ULONG g_shadowssdtoffset = 0x50;				//进程在SSDT表中偏移

ULONG g_PspTerminateThreadByPointerAddr;		//PspTerminateThreadByPointer函数地址
ULONG g_NtOpenProcessAddr;						//NtOpenProcess函数地址
ULONG g_NtTerminateProcessAddr;					//NtTerminateProcess函数地址
PSGETNEXTPROCESSTHREAD PsGetNextProcessThread;  //PsGetNextProcessThread函数地址

FAST_MUTEX mux_protect;							//快速互斥体用于操作链表
PVOID g_ShareBuf;

#endif	// End of __PROTECTPROCESS_H__ 

//*============================================================================ 
//*= = 文件结束 
//*============================================================================ 
