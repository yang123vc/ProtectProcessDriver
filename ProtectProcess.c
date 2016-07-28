/*
*******************************************************************************
*= = 文件名称：ProtectProcess.h
*= = 文件描述：关于ProtectProcess的头文件
*= = 作    者：indigo
*= = 编写时间：2016-07-09 19:18:00
*******************************************************************************
*/

#include "ProtectProcess.h"

BOOLEAN unProtectProcessById(ULONG uPid, ULONG user);

//*============================================================================
//*= = 函数名称：RemoveProtect
//*= = 功能描述：去掉内存保护函数 
//*= = 入口参数：NULL 
//*= = 出口参数：VOID
//*============================================================================
VOID RemoveProtect()
{
	_asm
	{
		cli;								//关中断
		mov eax, cr0;						//寄存器CR0包含系统的控制标志，用于控制处理器的操作模式和状态
		and eax, not 10000h;				//取eax的后16位
		mov cr0, eax;						//写回cr0寄存器
	}
}

//*============================================================================
//*= = 函数名称：RemoveProtect
//*= = 功能描述：恢复内存保护函数 
//*= = 入口参数：NULL 
//*= = 出口参数：VOID
//*============================================================================
VOID ResumeProtect()
{
	_asm
	{
		mov eax, cr0;			    
		or  eax, 10000h;					//恢复之前and操作的结果
		mov cr0, eax;
		sti;								//开中断
	}
}

//*============================================================================
//*= = 函数名称：StrEqual
//*= = 功能描述：字符串比较函数 
//*= = 入口参数：PWSTR,PWSTR
//*= = 出口参数：BOOLEAN
//*============================================================================
BOOLEAN StrEqual(PWSTR wstr1, PWSTR wstr2)
{
	PWCHAR PWC1, PWC2;
	PWC1 = wstr1;
	PWC2 = wstr2;

	while (MmIsAddressValid((PVOID)PWC1) && MmIsAddressValid((PVOID)PWC2))	{
		if (*(PWC1) == 0 && *(PWC2) == 0)
			return TRUE;
		if (*(PWC1) != *(PWC2))
			return FALSE;
		PWC1++;
		PWC2++;
	}
	return FALSE;
}

//*============================================================================
//*= = 函数名称：StrEqual
//*= = 功能描述：插入链表函数 
//*= = 入口参数：PLISTNODE,PLISTNODE
//*= = 出口参数：VOID
//*============================================================================
VOID InsertNode(PLISTNODE *head, PLISTNODE data)//data表示新节点的地址
{
	PLISTNODE p;

	if (*head == NULL){
		*head = data;
	}
	else{
		p = *head;
		while (p->next != NULL){
			p = p->next;
		}
		p->next = data;
	}
}

//*============================================================================
//*= = 函数名称：RemoveNodeByUser
//*= = 功能描述：按用户删除链表节点函数 
//*= = 入口参数：PLISTNODE,ULONG
//*= = 出口参数：VOID
//*============================================================================
VOID RemoveNodeByUser(PLISTNODE *head, ULONG user)
{
	PLISTNODE p, t;

	p = *head;
	if (p == NULL){
		return;
	}

	//头结点
	if (StrEqual((PWSTR)p->data, (PWSTR)user)){
		*head = (*head)->next;
		ExFreePool((PVOID)p->data);
		ExFreePool((PVOID)p);
	}
	else{
	//非头结点
		while (p->next != NULL){
			if (StrEqual((PWSTR)p->next->data, (PWSTR)user))
			{
				t = p->next->next;
				ExFreePool((PVOID)p->next->data);
				ExFreePool((PVOID)p->next);
				p->next = t;
				break;
			}
			p = p->next;
		}
	}
}

//*============================================================================
//*= = 函数名称：RemoveNode
//*= = 功能描述：删除链表节点函数 
//*= = 入口参数：PLISTNODE,ULONG,ULONG
//*= = 出口参数：VOID
//*============================================================================
VOID RemoveNode(PLISTNODE *head, ULONG ProcessId, ULONG user)
{
	PLISTNODE p, a, b;
	PPROTECTINFO pt;

	ExAcquireFastMutex(&mux_protect);
	p = *head;
	if (p == NULL){								//链表为空
		ExReleaseFastMutex(&mux_protect);
		return;
	}

	if (*(PULONG)(p->data) == ProcessId){		//链表头符合
		pt = (PPROTECTINFO)p->data;
		a = pt->AllowedUser;					//授权用户
		//删除所有节点
		if (user == 0){
			while (a){
				b = a->next;
				ExFreePool((PVOID)a->data);		//释放内存
				ExFreePool((PVOID)a);
				a = b;
			}
			*head = (*head)->next;
			ExFreePool((PVOID)p->data);
			ExFreePool((PVOID)p);
		}
		else{
			RemoveNodeByUser(&pt->AllowedUser, user);
		}
	}
	else{										//其他位置符合
		while (p->next != NULL){
			if (*(PULONG)p->next->data == ProcessId){
				if (user == 0){
					pt = (PPROTECTINFO)p->next->data;
					a = pt->AllowedUser;
					while (a){
						b = a->next;
						ExFreePool((PVOID)a->data);
						ExFreePool((PVOID)a);
						a = b;
					}
					ExFreePool((PVOID)p->next->data);
					a = p->next->next;
					ExFreePool((PVOID)p->next);
					p->next = a;
				}
				else{
					RemoveNodeByUser(&((PPROTECTINFO)p->next->data)->AllowedUser, user);
				}
				break;
			}
			p = p->next;
		}
	}
	ExReleaseFastMutex(&mux_protect);
}

//*============================================================================
//*= = 函数名称：IsInProtectList
//*= = 功能描述：遍历链表函数 
//*= = 入口参数：ULONG,ULONG,BOOLEAN
//*= = 出口参数：PLISTNODE
//*============================================================================
PLISTNODE IsInProtectList(ULONG ProcessId, ULONG user, BOOLEAN b_ignoreuser)
{
	PLISTNODE p, t;
	ExAcquireFastMutex(&mux_protect);//申请互斥变量
	p = ProtectList;

	while (p){
		if (*(PULONG)(p->data) == ProcessId){
			if (user == 0 || b_ignoreuser){//未设置或者忽视授权用户
				ExReleaseFastMutex(&mux_protect);
				return p;
			}
			t = ((PPROTECTINFO)(p->data))->AllowedUser;
			while (t){
				if (StrEqual((PWSTR)(t->data), (PWSTR)user)){
					ExReleaseFastMutex(&mux_protect);
					return p;
				}
				t = t->next;
			}
			ExReleaseFastMutex(&mux_protect);
			return NULL;
		}
		p = p->next;
	}
	ExReleaseFastMutex(&mux_protect);
	return NULL;
}

//*============================================================================
//*= = 函数名称：GetListCount
//*= = 功能描述：获取所有节点信息函数 
//*= = 入口参数：PLISTNODE,PULONG
//*= = 出口参数：ULONG
//*============================================================================
ULONG GetListCount(IN PLISTNODE list, OUT PULONG PidTable)
{
	ULONG count = 0;

	while (list){
		PidTable[count] = *(PULONG)list->data;
		count++;
		list = list->next;
	}
	return count;
}

//*============================================================================
//*= = 函数名称：FreeList
//*= = 功能描述：释放所有节点函数 
//*= = 入口参数：NULL
//*= = 出口参数：VOID
//*============================================================================
VOID FreeList()
{
	PULONG PidTable;
	ULONG count, i;

	PidTable = (PULONG)ExAllocatePool(NonPagedPool, sizeof(ULONG)*MAX_PROCESS);
	memset((PVOID)PidTable, 0, sizeof(ULONG)*MAX_PROCESS);

	ExAcquireFastMutex(&mux_protect);

	count = GetListCount(ProtectList, PidTable);

	ExReleaseFastMutex(&mux_protect);
	for (i = 0; i < count; i++)
	{
		unProtectProcessById(PidTable[i], 0);
	}
	ExFreePool(PidTable);
}

//*============================================================================
//*= = 函数名称：GetFuncAddr
//*= = 功能描述：获取指定函数内存地址函数 
//*= = 入口参数：PWSTR
//*= = 出口参数：ULONG
//*============================================================================
ULONG GetFuncAddr(PWSTR pwszFuncName)
{
	UNICODE_STRING uniFuncName;
	RtlInitUnicodeString(&uniFuncName, pwszFuncName);
	return (ULONG)MmGetSystemRoutineAddress(&uniFuncName);
}

//*============================================================================
//*= = 函数名称：GetPspTerminateThreadByPointerAddr
//*= = 功能描述：获取PspTerminateSystemThread函数地址 
//*= = 入口参数：NULL
//*= = 出口参数：ULONG
//*============================================================================
ULONG GetPspTerminateThreadByPointerAddr()
{
	ULONG FunAddress = 0, i = 0;

	//先获取PsTerminateSystemThread这个函数地址.他调用了PspTerminateThreadByPointer
	//这个函数本身并没有被导出,所以通过搜索特征.定位call 然后将call的地址进行运算即可
	FunAddress = GetFuncAddr(L"PsTerminateSystemThread");

	//如果获取失败
	if (FunAddress == 0){
		return 0L;
	}

	//目标地址=下条指令的地址+机器码E8后面所跟的32位数
	for (i = FunAddress; i < FunAddress + 0xff; i++){
		if (*(PUCHAR)i == 0x50 && *(PUCHAR)(i + 1) == 0xe8){//特征码 0x50 0xe8——push eax call
			return (ULONG)(*(PULONG)(i + 2) + i + 2 + 4);
		}
	}
	return 0L;
}

//*============================================================================
//*= = 函数名称：GetNtOpenProcessAddr
//*= = 功能描述：获取NtOpenProcess函数地址 
//*= = 入口参数：NULL
//*= = 出口参数：ULONG
//*============================================================================
ULONG GetNtOpenProcessAddr()
{
	ULONG uZwFuncAddr = 0, uIndex = 0;

	uZwFuncAddr = GetFuncAddr(L"ZwOpenProcess");
	if (uZwFuncAddr == 0){
		return 0L;
	}

	uIndex = *(PULONG)(uZwFuncAddr + 1);
	return KeServiceDescriptorTable.ServiceTableBase[uIndex];
}

//*============================================================================
//*= = 函数名称：GetNtTerminateProcessAddr
//*= = 功能描述：获取NtTerminateProcess函数地址 
//*= = 入口参数：NULL
//*= = 出口参数：ULONG
//*============================================================================
ULONG GetNtTerminateProcessAddr()
{
	ULONG uZwFuncAddr = 0, uIndex = 0;

	uZwFuncAddr = GetFuncAddr(L"ZwTerminateProcess");
	if (uZwFuncAddr == 0){
		return 0L;
	}

	uIndex = *(PULONG)(uZwFuncAddr + 1);
	return KeServiceDescriptorTable.ServiceTableBase[uIndex];
}

//*============================================================================
//*= = 函数名称：GetPsGetNextProcessThreadAddr
//*= = 功能描述：获取PsGetNextProcessThread函数地址 
//*= = 入口参数：NULL
//*= = 出口参数：ULONG
//*============================================================================
ULONG GetPsGetNextProcessThreadAddr()
{
	ULONG uFuncAddr = 0, i = 0;

	uFuncAddr = GetFuncAddr(L"PsResumeProcess");
	if (uFuncAddr == 0){
		return 0L;
	}

	for (i = uFuncAddr; i < uFuncAddr + 0xff; i++){
		if (*(PUCHAR)i == 0x08 && *(PUCHAR)(i + 1) == 0xe8){//特征码0x08 0xe8
			return (ULONG)(*(PULONG)(i + 2) + 5 + i + 1);
		}
	}
	return 0L;
}

//*============================================================================
//*= = 函数名称：GetProcessOwner
//*= = 功能描述：获取进程的所属用户 (local unique)
//*= = 入口参数：PEPROCESS
//*= = 出口参数：ULONG
//*============================================================================
ULONG GetProcessOwner(PEPROCESS Process)
{
	NTSTATUS status;
	PACCESS_TOKEN token;
	LUID luid;
	PSECURITY_USER_DATA secdata;
	ULONG user;

	token = PsReferencePrimaryToken(Process);
	status = SeQueryAuthenticationIdToken(token, &luid);
	if (!NT_SUCCESS(status)){
		PsDereferencePrimaryToken(token);
		return 0L;
	}
	PsDereferencePrimaryToken(token);

	//根据用户的luid取用户名
	status = GetSecurityUserInfo(&luid, UNDERSTANDS_LONG_NAMES, &secdata);
	if (!NT_SUCCESS(status)){
		return 0L;
	}
	
	//用完后需要自己释放
	user = (ULONG)ExAllocatePool(NonPagedPool, secdata->UserName.Length + sizeof(WCHAR));
	if (!user){
		return 0L;
	}
	memset((PVOID)user, 0, secdata->UserName.Length + sizeof(WCHAR));
	memcpy((PVOID)user, (PVOID)secdata->UserName.Buffer, secdata->UserName.Length);
	return user;
}

//*============================================================================
//*= = 函数名称：GetCsrssEprocess
//*= = 功能描述：获取csrss进程句柄 
//*= = 入口参数：NULL
//*= = 出口参数：PEPROCESS
//*============================================================================
PEPROCESS GetCsrssEprocess()//用于维持Windows的控制
{
	PEPROCESS Process;
	PLIST_ENTRY List, p;
	PSTR Name;

	Process = PsGetCurrentProcess();
	List = (PLIST_ENTRY)((ULONG)Process + g_ProcessListOffset);
	p = List;
	do
	{
		Name = (PSTR)((ULONG)p + g_ProcessNameOffset - g_ProcessListOffset);
		if (strstr(Name, "csrss.exe"))//判断是否是csrss进程
			return (PEPROCESS)((ULONG)p - g_ProcessListOffset);
		p = p->Blink;//指向前一个元素
	} while (p != List);
	return NULL;
}

//*============================================================================
//*= = 函数名称：OriginPspTerminateThreadByPointer
//*= = 功能描述：跳转回原来的处理函数PspTerminateThreadByPointer
//*= = 入口参数：PETHREAD,NTSTATUS,BOOLEAN
//*= = 出口参数：NTSTATUS
//*============================================================================
NTSTATUS __declspec(naked) OriginPspTerminateThreadByPointer(
	IN PETHREAD Thread,
	IN NTSTATUS ExitStatus,
	IN BOOLEAN DirectTerminate
	)
{
	_asm
	{
		mov edi, edi;
		push ebp;
		mov ebp, esp;
		mov eax, [g_PspTerminateThreadByPointerAddr];
		add eax, 5;
		jmp eax;
	}
}

//*============================================================================
//*= = 函数名称：OriginNtOpenProcess
//*= = 功能描述：跳转回原来的处理函数NtOpenProcess 
//*= = 入口参数：PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PCLIENT_ID
//*= = 出口参数：NTSTATUS
//*============================================================================
NTSTATUS __declspec(naked) OriginNtOpenProcess(
	__out PHANDLE ProcessHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in_opt PCLIENT_ID ClientId
	)
{
	_asm
	{
		mov edi, edi;
		push ebp;
		mov ebp, esp;
		mov eax, [g_NtOpenProcessAddr];
		add eax, 5;
		jmp eax;
	}
}

//*============================================================================
//*= = 函数名称：OriginNtTerminateProcess
//*= = 功能描述：跳转回原来的NtTerminateProcess函数
//*= = 入口参数：HANDLE,NTSTATUS
//*= = 出口参数：NTSTATUS
//*============================================================================
NTSTATUS __declspec(naked) OriginNtTerminateProcess(
	__in_opt HANDLE ProcessHandle,
	__in NTSTATUS ExitStatus
	)
{
	_asm
	{
		mov edi, edi;
		push ebp;
		mov ebp, esp;
		mov eax, [g_NtTerminateProcessAddr];
		add eax, 5;
		jmp eax;
	}
}

//*============================================================================
//*= = 函数名称：HookPspTerminateThreadByPointer
//*= = 功能描述：Hook的PspTerminateThreadByPointer函数 
//*= = 入口参数：PETHREAD,NTSTATUS,BOOLEAN
//*= = 出口参数：NTSTATUS
//*============================================================================
NTSTATUS HookPspTerminateThreadByPointer(
	IN PETHREAD Thread,
	IN NTSTATUS ExitStatus,
	IN BOOLEAN DirectTerminate
	)
{
	PEPROCESS Killer, Prey;
	ULONG KillerId, PreyId, user;
	Killer = PsGetCurrentProcess();
	Prey = IoThreadToProcess(Thread);
	KillerId = *(PULONG)((ULONG)Killer + g_ProcessIdOffset);
	PreyId = *(PULONG)((ULONG)Prey + g_ProcessIdOffset);
	if (KillerId != PreyId)
	{
		if (IsInProtectList(PreyId, 0, TRUE))//查看保护列表
		{
			user = GetProcessOwner(Killer);
			if (!IsInProtectList(PreyId, user, FALSE))//查看保护列表
			{
				if (user)
					ExFreePool((PVOID)user);
				KdPrint(("[*]HookPspTerminateThreadByPointer:stop %s killing %s", (PUCHAR)((ULONG)Killer + g_ProcessNameOffset), (PUCHAR)((ULONG)Prey + g_ProcessNameOffset)));
				return STATUS_ACCESS_DENIED;
			}
			if (user)
				ExFreePool((PVOID)user);
		}
	}
	return OriginPspTerminateThreadByPointer(Thread, ExitStatus, DirectTerminate);
}

//*============================================================================
//*= = 函数名称：HookNtOpenProcess
//*= = 功能描述：Hook的NtOpenProcess函数 
//*= = 入口参数：PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PCLIENT_ID
//*= = 出口参数：NTSTATUS
//*============================================================================
NTSTATUS HookNtOpenProcess(
	__out PHANDLE ProcessHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in_opt PCLIENT_ID ClientId
	)
{
	PEPROCESS Prey, Killer;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG KillerId, PreyId, user;

	status = PsLookupProcessByProcessId(ClientId->UniqueProcess, &Prey);
	if (NT_SUCCESS(status))
	{

		ObDereferenceObject(Prey);
		Killer = PsGetCurrentProcess();
		KillerId = *(PULONG)((ULONG)Killer + g_ProcessIdOffset);
		PreyId = *(PULONG)((ULONG)Prey + g_ProcessIdOffset);

		if (KillerId != PreyId)
		{
			if (IsInProtectList(PreyId, 0, TRUE))
			{
				user = GetProcessOwner(Killer);
				KdPrint(("%ws", (PWSTR)user));
				if (!IsInProtectList(PreyId, user, FALSE))
				{
					DesiredAccess &= ~PROCESS_TERMINATE;
					DesiredAccess &= ~PROCESS_CREATE_THREAD;
					DesiredAccess &= ~PROCESS_SET_SESSIONID;
					DesiredAccess &= ~PROCESS_VM_OPERATION;
					DesiredAccess &= ~PROCESS_VM_READ;
					DesiredAccess &= ~PROCESS_VM_WRITE;
					KdPrint(("[*]HookNtOpenProcess: limit %s's using of %s", (PUCHAR)((ULONG)Killer + g_ProcessNameOffset), (PUCHAR)((ULONG)Prey + g_ProcessNameOffset)));
				}
				if (user)

					ExFreePool((PVOID)user);
			}
		}
	}
	return OriginNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);//处理之后传回系统原函数继续处理
}

//*============================================================================
//*= = 函数名称：HookNtTerminateProcess
//*= = 功能描述：Hook的NtTerminateProcess函数
//*= = 入口参数：HANDLE,NTSTATUS
//*= = 出口参数：NTSTATUS
//*============================================================================
NTSTATUS HookNtTerminateProcess(
	__in_opt HANDLE ProcessHandle,
	__in NTSTATUS ExitStatus
	)
{
	PEPROCESS Killer, Prey;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	GETPREVIOUSMODE KeGetPreviousMode;
	ULONG KillerId, PreyId, user;

	KeGetPreviousMode = (GETPREVIOUSMODE)GetFuncAddr(L"KeGetPreviousMode");
	status = ObReferenceObjectByHandle(ProcessHandle, PROCESS_TERMINATE, *PsProcessType, KeGetPreviousMode(), &Prey, NULL);
	if (NT_SUCCESS(status))
	{
		ObDereferenceObject(Prey);
		Killer = PsGetCurrentProcess();

		KillerId = *(PULONG)((ULONG)Killer + g_ProcessIdOffset);
		PreyId = *(PULONG)((ULONG)Prey + g_ProcessIdOffset);
		if (KillerId != PreyId)
		{
			if (IsInProtectList(PreyId, 0, TRUE))
			{
				user = GetProcessOwner(Killer);
				if (!IsInProtectList(PreyId, user, FALSE))
				{
					if (user)
						ExFreePool((PVOID)user);
					KdPrint(("[*]HookNtTerminateProcess:stop %s killing %s", (PUCHAR)((ULONG)Killer + g_ProcessNameOffset), (PUCHAR)((ULONG)Prey + g_ProcessNameOffset)));
					return STATUS_ACCESS_DENIED;
				}
				if (user)
					ExFreePool((PVOID)user);
			}
		}

	}
	return OriginNtTerminateProcess(ProcessHandle, ExitStatus);
}

//*============================================================================
//*= = 函数名称：UsePsGetNextProcessThread
//*= = 功能描述：调用PsGetNextProcessThread函数获取下一个线程的句柄 
//*= = 入口参数：PEPROCESS，PETHREAD
//*= = 出口参数：PETHREAD
//*============================================================================
PETHREAD UsePsGetNextProcessThread(
	IN PEPROCESS Process,
	IN PETHREAD Thread
	)
{
	PETHREAD nextThread = NULL;

	_asm
	{
		mov  eax, Process;
		push Thread;
		call PsGetNextProcessThread;
		mov  nextThread, eax;
	}
	return nextThread;
}

//*============================================================================
//*= = 函数名称：HookSystemRoutine
//*= = 功能描述：安装钩子
//*= = 入口参数：ULONG，ULONG
//*= = 出口参数：VOID
//*============================================================================
VOID HookSystemRoutine(ULONG uOldAddr, ULONG uNewAddr)
{
	UCHAR jmpcode[5];

	if (!(MmIsAddressValid((PVOID)uOldAddr) && MmIsAddressValid((PVOID)uNewAddr)))
	{
		KdPrint(("[*]Invalid address!"));
		return;
	}
	jmpcode[0] = 0xe9;
	*(PULONG)(jmpcode + 1) = uNewAddr - uOldAddr - 5;
	RemoveProtect();
	memcpy((PVOID)uOldAddr, (PVOID)jmpcode, 5);
	ResumeProtect();
}

//*============================================================================
//*= = 函数名称：UnhookSystemRoutine
//*= = 功能描述：卸载钩子 
//*= = 入口参数：ULONG，PCHAR
//*= = 出口参数：VOID
//*============================================================================
VOID UnhookSystemRoutine(ULONG uOldAddr, PCHAR pOriCode)
{
	if (!MmIsAddressValid((PVOID)uOldAddr))
	{
		KdPrint(("[*]Invalid address"));
		return;
	}
	RemoveProtect();
	memcpy((PVOID)uOldAddr, (PVOID)pOriCode, 5);
	ResumeProtect();
}

//*============================================================================
//*= = 函数名称：ProtectProcessById
//*= = 功能描述：添加进程到保护链表 
//*= = 入口参数：ULONG，ULONG
//*= = 出口参数：BOOLEAN
//*============================================================================
BOOLEAN ProtectProcessById(ULONG uPid, ULONG user)
{
	PLISTNODE node, p;
	PPROTECTINFO protectinfo;

	if (IsInProtectList(uPid, user, FALSE))
	{
		return FALSE;
	}
	else if ((p = IsInProtectList(uPid, user, TRUE)) != NULL)
	{
		protectinfo = (PPROTECTINFO)p->data;
		node = (PLISTNODE)ExAllocatePool(NonPagedPool, sizeof(LISTNODE));
		node->next = NULL;
		node->data = user;
		ExAcquireFastMutex(&mux_protect);
		InsertNode(&protectinfo->AllowedUser, node);
		ExReleaseFastMutex(&mux_protect);
	}
	else
	{
		node = (PLISTNODE)ExAllocatePool(NonPagedPool, sizeof(LISTNODE));
		protectinfo = (PPROTECTINFO)ExAllocatePool(NonPagedPool, sizeof(PROTECTINFO));
		node->next = NULL;
		node->data = (ULONG)protectinfo;
		protectinfo->ProcessId = uPid;
		protectinfo->AllowedUser = NULL;
		if (user != 0)
		{
			p = (PLISTNODE)ExAllocatePool(NonPagedPool, sizeof(LISTNODE));
			p->next = NULL;
			p->data = user;
			InsertNode(&protectinfo->AllowedUser, p);
			protectinfo->AllowedUser = p;
		}
		ExAcquireFastMutex(&mux_protect);
		InsertNode(&ProtectList, node);
		ExReleaseFastMutex(&mux_protect);
	}
	return TRUE;
}

//*============================================================================
//*= = 函数名称：unProtectProcessById
//*= = 功能描述：在保护链表中去掉进程
//*= = 入口参数：ULONG，ULONG
//*= = 出口参数：ULONG
//*============================================================================
BOOLEAN unProtectProcessById(ULONG uPid, ULONG user)
{
	//判断进程是否存在于保护链表中
	if (IsInProtectList(uPid, user, FALSE) == NULL){
		return FALSE;
	}
	RemoveNode(&ProtectList, uPid, user);
	return TRUE;
}

//*============================================================================
//*= = 函数名称：KillProcessById
//*= = 功能描述：通过ID杀死进程 
//*= = 入口参数：ULONG
//*= = 出口参数：BOOLEAN
//*============================================================================
BOOLEAN KillProcessById(ULONG uPid)
{
	PEPROCESS Process;
	PETHREAD Thread;
	NTSTATUS status;

	//判断PsGetNextProcessThread函数地址是否可用
	if (!MmIsAddressValid((PVOID)(ULONG)PsGetNextProcessThread))
	{
		KdPrint(("[*]PsGetNextProcessThread address is invalid."));
		return FALSE;
	}

	//获取进程句柄
	status = PsLookupProcessByProcessId((HANDLE)uPid, &Process);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[*]Get process handle failed in KillProcessById function."));
		return FALSE;
	}

	unProtectProcessById(uPid, 0);

	//依次杀死进程的所有线程
	RtlInterlockedSetBitsDiscardReturn((PULONG)((ULONG)Process + g_ProcessFlagsOffset), PS_PROCESS_FLAGS_PROCESS_DELETE);
	for (Thread = UsePsGetNextProcessThread(Process, NULL); Thread != NULL; Thread = UsePsGetNextProcessThread(Process, Thread))
	{
		HookPspTerminateThreadByPointer(Thread, 0, TRUE);
	}
	ObDereferenceObjectDeferDelete(Process);
	return TRUE;
}

//*============================================================================
//*= = 函数名称：CreateProecssCallback
//*= = 功能描述：创建进程的通知例程 
//*= = 入口参数：HANDLE,HANDLE,BOOLEAN
//*= = 出口参数：VOID
//*============================================================================
VOID CreateProecssCallback(
	IN HANDLE  ParentId,
	IN HANDLE  ProcessId,
	IN BOOLEAN  Create
	)
{
	NTSTATUS status;
	PPROCESSINFO ProcessInfo = (PPROCESSINFO)((ULONG)g_ShareBuf + sizeof(ULONG));
	PEPROCESS Process;
	UNICODE_STRING NameW;
	ANSI_STRING NameA;
	if (!MmIsAddressValid((PVOID)g_ShareBuf))
		return;
	memset((PVOID)ProcessInfo, 0, sizeof(PROCESSINFO));

	if (Create){
		//创建进程
		*(PULONG)g_ShareBuf = TRUE;
		ProcessInfo->ProcessId = (ULONG)ProcessId;

		status = PsLookupProcessByProcessId(ProcessId, &Process);
		if (!NT_SUCCESS(status))
		{
			KdPrint(("[*]Get process handle failed in Createcallback."));
		}

		RtlInitAnsiString(&NameA, (PCSZ)((ULONG)Process + g_ProcessNameOffset));
		RtlAnsiStringToUnicodeString(&NameW, &NameA, TRUE);

		ObDereferenceObject(Process);

		memcpy((PVOID)ProcessInfo->Name, (PVOID)NameW.Buffer, NameW.Length);

		//KdPrint(("[*]USER:%wZ", NameW));

		RtlFreeUnicodeString(&NameW);
	}
	else{
		//从保护进程和隐藏进程链表中去掉
		unProtectProcessById((ULONG)ProcessId, 0);
	}
}

//*============================================================================
//*= = 函数名称：Unload
//*= = 功能描述：卸载驱动
//*= = 入口参数：PDRIVER_OBJECT
//*= = 出口参数：VOID
//*============================================================================
VOID Unload(PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING Win32Device;

	//释放列表
	FreeList();

	//卸载所有钩子
	UnhookSystemRoutine(g_PspTerminateThreadByPointerAddr, "\x8b\xff\x55\x8b\xec");
	UnhookSystemRoutine(g_NtTerminateProcessAddr, "\x8b\xff\x55\x8b\xec");
	UnhookSystemRoutine(g_NtOpenProcessAddr, "\x8b\xff\x55\x8b\xec");

	//移除通知例程
	PsSetCreateProcessNotifyRoutine(CreateProecssCallback, TRUE);

	//释放内存
	if (g_ShareBuf)
	{
		ExFreePool(g_ShareBuf);
	}

	IoUnregisterShutdownNotification(DriverObject->DeviceObject);

	//移除设备
	RtlInitUnicodeString(&Win32Device, SYMBOL_NAME);
	IoDeleteSymbolicLink(&Win32Device);
	IoDeleteDevice(DriverObject->DeviceObject);
}

//*============================================================================
//*= = 函数名称：CreateClose
//*= = 功能描述：对开启关闭Irp的派遣函数 
//*= = 入口参数：PDEVICE_OBJECT,PIRP
//*= = 出口参数：NTSTATUS
//*============================================================================
NTSTATUS CreateClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

//*============================================================================
//*= = 函数名称：DefaultHandler
//*= = 功能描述：默认派遣函数 
//*= = 入口参数：PDEVICE_OBJECT,PIRP
//*= = 出口参数：NTSTATUS
//*============================================================================
NTSTATUS DefaultHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_NOT_SUPPORTED;
}

//*============================================================================
//*= = 函数名称：DeviceControl
//*= = 功能描述：设备控制派遣函数 
//*= = 入口参数：PDEVICE_OBJECT,PIRP
//*= = 出口参数：NTSTATUS
//*============================================================================
NTSTATUS DeviceControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NTSTATUS status = STATUS_SUCCESS;

	PIO_STACK_LOCATION INFO = IoGetCurrentIrpStackLocation(Irp);
	ULONG ControlCode = INFO->Parameters.DeviceIoControl.IoControlCode;
	PVOID inbuf = Irp->AssociatedIrp.SystemBuffer;
	PVOID outbuf = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
	ULONG outlen = INFO->Parameters.DeviceIoControl.OutputBufferLength;

	PPROCESSINFO p;
	ULONG len, user, i;
	PLISTNODE list;
	PPROTECTINFO pt;

	//判断控制码
	switch (ControlCode)
	{
		case PROTECTBYPID:
			p = (PPROCESSINFO)inbuf;
			len = wcslen(p->Name);
			user = 0;

			//如果Name不为空，则复制到user中
			if (len){
				user = (ULONG)ExAllocatePool(NonPagedPool, (len + 1)*sizeof(WCHAR));
				wcscpy((PWSTR)user, p->Name);
			}

			*(PULONG)outbuf = ProtectProcessById(p->ProcessId, user) ? 1 : 0;
			break;
		case UNPROTECTBYPID:
			p = (PPROCESSINFO)inbuf;
			len = wcslen(p->Name);
			user = 0;

			//如果Name不为空，则复制到user中
			if (len){
				user = (ULONG)ExAllocatePool(NonPagedPool, (len + 1)*sizeof(WCHAR));
				wcscpy((PWSTR)user, p->Name);
			}

			*(PULONG)outbuf = unProtectProcessById(p->ProcessId, user) ? 1 : 0;
			if (user){//释放内存
				ExFreePool((PVOID)user);
			}
			break;
		case KILLBYPID:	
			*(PULONG)outbuf = KillProcessById(*(PULONG)inbuf) ? 1 : 0;
			break;
		default:
			break;
	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = outlen;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

//*============================================================================
//*= = 函数名称：Shutdown
//*= = 功能描述：处理关闭命令 
//*= = 入口参数：PDEVICE_OBJECT,PIRP
//*= = 出口参数：NTSTATUS
//*============================================================================
NTSTATUS Shutdown(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	PDRIVER_OBJECT DriverObject;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	UNICODE_STRING DriverName;
	OBREFERENCEOBJECTBYNAME ObReferenceObjectByName = (OBREFERENCEOBJECTBYNAME)GetFuncAddr(L"ObReferenceObjectByName");
	RtlInitUnicodeString(&DriverName, DRIVER_NAME);
	if (MmIsAddressValid((PVOID)(ULONG)ObReferenceObjectByName)){
		status = ObReferenceObjectByName(
			&DriverName,
			OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
			NULL,
			0,
			*IoDriverObjectType,
			KernelMode,
			NULL,
			(PVOID*)&DriverObject
			);
		if (NT_SUCCESS(status)){
			Unload(DriverObject);//卸载驱动对象
		}
	}
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

//*============================================================================
//*= = 函数名称：DriverEntry
//*= = 功能描述：驱动程序入口函数 
//*= = 入口参数：PDRIVER_OBJECT, PUNICODE_STRING 
//*= = 出口参数：NTSTATUS
//*============================================================================
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNICODE_STRING DeviceName, Win32Device;
	PDEVICE_OBJECT DeviceObject = NULL;
	NTSTATUS status;
	ULONG i;

	DriverObject->DriverUnload = Unload;
	RtlInitUnicodeString(&DeviceName, DEVICE_NAME);
	RtlInitUnicodeString(&Win32Device, SYMBOL_NAME);

	// 处理派遣例程
	for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		DriverObject->MajorFunction[i] = DefaultHandler;
	}
	DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;			//创建设备，CreateFile会产生此IRP
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;			//关闭设备，CloseHandle会产生此IRP
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;	//DeviceControl函数会产生此IRP
	DriverObject->MajorFunction[IRP_MJ_SHUTDOWN] = Shutdown;			//关闭系统前会产生此IRP

	//创建设备
	status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
	if (!NT_SUCCESS(status))
		return status;
	if (!DeviceObject)
		return STATUS_UNEXPECTED_IO_ERROR;
	

	// 创建符号链接 
	status = IoCreateSymbolicLink(&Win32Device, &DeviceName);
	if (!NT_SUCCESS(status)){
		IoDeleteDevice(DeviceObject);
		return status;
	}
	//指定通信方式
	DeviceObject->Flags |= DO_DIRECT_IO;
	DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	IoRegisterShutdownNotification(DeviceObject);

	//初始化互斥信号量
	ExInitializeFastMutex(&mux_protect);

	//获取各种函数的地址
	g_PspTerminateThreadByPointerAddr = GetPspTerminateThreadByPointerAddr();//TerminateProcess其实是通过遍历进程的线程链表，然后调PspTerminateThreadByPointer这个函数来结束进程的。
	g_NtTerminateProcessAddr = GetNtTerminateProcessAddr();
	g_NtOpenProcessAddr = GetNtOpenProcessAddr();
	PsGetNextProcessThread = (PSGETNEXTPROCESSTHREAD)GetPsGetNextProcessThreadAddr();

	//注册事件通知 创建进程时调用CreateProecssCallback
	PsSetCreateProcessNotifyRoutine(CreateProecssCallback, FALSE);

	//安装钩子到各个函数
	HookSystemRoutine(g_PspTerminateThreadByPointerAddr, (ULONG)HookPspTerminateThreadByPointer);
	HookSystemRoutine(g_NtTerminateProcessAddr, (ULONG)HookNtTerminateProcess);
	HookSystemRoutine(g_NtOpenProcessAddr, (ULONG)HookNtOpenProcess);

	//用一个ULONG的空间用于判断创建还是结束进程。
	g_ShareBuf = ExAllocatePool(NonPagedPool, sizeof(ULONG)+sizeof(PROCESSINFO));

	return STATUS_SUCCESS;
}
