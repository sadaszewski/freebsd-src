#include <efi.h>
#include <efilib.h>
#include <efichar.h>

#include <IndustryStandard/Tpm20.h>
#include <Protocol/Tcg2Protocol.h>


#define RC_NV_ReadPublic_nvIndex	(TPM_RC_H + TPM_RC_1)
#define RC_NV_Read_authHandle		(TPM_RC_H + TPM_RC_1)
#define RC_NV_Read_nvIndex		(TPM_RC_H + TPM_RC_2)


#ifndef EFI_SECURITY_VIOLATION
#define EFI_SECURITY_VIOLATION	EFIERR(26)
#endif


#pragma pack(1)

typedef struct {
	TPM2_COMMAND_HEADER	Header;
	TPMI_RH_NV_INDEX		NvIndex;
} TPM2_NV_READPUBLIC_COMMAND;


typedef struct {
	TPM2_RESPONSE_HEADER	Header;
	TPM2B_NV_PUBLIC			NvPublic;
	TPM2B_NAME				NvName;
} TPM2_NV_READPUBLIC_RESPONSE;

typedef struct {
	TPM2_COMMAND_HEADER	Header;
	TPMI_RH_NV_AUTH		AuthHandle;
	TPMI_RH_NV_INDEX		NvIndex;
	UINT32					AuthSessionSize;
	TPMS_AUTH_COMMAND		AuthSession;
	UINT16					Size;
	UINT16					Offset;
} TPM2_NV_READ_COMMAND;

typedef struct {
	TPM2_RESPONSE_HEADER	Header;
	UINT32					AuthSessionSize;
	TPM2B_MAX_BUFFER		Data;
	TPMS_AUTH_RESPONSE		AuthSession;
} TPM2_NV_READ_RESPONSE;

#pragma pack()


static INT16 SwapBytes16 (UINT16 Value) {
	return (UINT16) ((Value<< 8) | (Value>> 8));
}


static UINT32 SwapBytes32 (UINT32 Value) {
	UINT32  LowerBytes;
	UINT32  HigherBytes;

	LowerBytes  = (UINT32) SwapBytes16 ((UINT16) Value);
	HigherBytes = (UINT32) SwapBytes16 ((UINT16) (Value >> 16));
	return (LowerBytes << 16 | HigherBytes);
}


static EFI_GUID mEfiTcg2ProtocolGuid = EFI_TCG2_PROTOCOL_GUID;
static EFI_TCG2_PROTOCOL *mTcg2Protocol = NULL;


static EFI_STATUS Tpm2SubmitCommand (
	UINT32	InputParameterBlockSize,
	UINT8	*InputParameterBlock,
	UINT32	*OutputParameterBlockSize,
	UINT8	*OutputParameterBlock) {
	
	EFI_STATUS				Status;
	TPM2_RESPONSE_HEADER	*Header;

	if (mTcg2Protocol == NULL) {
		Status = BS->LocateProtocol (&mEfiTcg2ProtocolGuid, NULL, (VOID **) &mTcg2Protocol);
		if (EFI_ERROR (Status)) {
			//
			// Tcg2 protocol is not installed. So, TPM2 is not present.
			//
			printf("Tpm2SubmitCommand - Tcg2 - %lu\n", Status);
			return EFI_NOT_FOUND;
		}
	}
	
	//
	// Assume when Tcg2 Protocol is ready, RequestUseTpm already done.
	//
	Status = mTcg2Protocol->SubmitCommand (
		mTcg2Protocol,
		InputParameterBlockSize,
		InputParameterBlock,
		*OutputParameterBlockSize,
		OutputParameterBlock
	);
	if (EFI_ERROR (Status)) {
		return Status;
	}
	Header = (TPM2_RESPONSE_HEADER *)OutputParameterBlock;
	*OutputParameterBlockSize = SwapBytes32 (Header->paramSize);

	return EFI_SUCCESS;
}


static UINT16 ReadUnaligned16 (const UINT16 *Buffer) {
	if (Buffer == NULL) {
		printf("Buffer is NULL in ReadUnaligned16\n");
		BS->Exit(IH, EFI_INVALID_PARAMETER, 0, NULL);
		return ((UINT16) -1);
	}
	return *Buffer;
}


static UINT32 ReadUnaligned32 (const UINT32 *Buffer) {
 	if (Buffer == NULL) {
		printf("Buffer is NULL in ReadUnaligned32\n");
		BS->Exit(IH, EFI_INVALID_PARAMETER, 0, NULL);
		return ((UINT32) -1);
	}
	return *Buffer;
}


static UINT16 WriteUnaligned16 (UINT16 *Buffer, UINT16 Value) {
	if (Buffer == NULL) {
		printf("NULL buffer passed to WriteUnaligned16\n");
		BS->Exit(IH, EFI_INVALID_PARAMETER, 0, NULL);
		return ((UINT16) -1);
	}

	return (*Buffer = Value);
}


static UINT32 WriteUnaligned32 (UINT32 *Buffer, UINT32 Value) {
	if (Buffer == NULL) {
		printf("Buffer is NULL in WriteUnaligned32\n");
		BS->Exit(IH, EFI_INVALID_PARAMETER, 0, NULL);
		return ((UINT32) -1);
	}

	return (*Buffer = Value);
}


EFI_STATUS Tpm2NvReadPublic (
	TPMI_RH_NV_INDEX NvIndex,
	TPM2B_NV_PUBLIC *NvPublic,
	TPM2B_NAME *NvName) {
	
	EFI_STATUS                        Status;
	TPM2_NV_READPUBLIC_COMMAND	SendBuffer;
	TPM2_NV_READPUBLIC_RESPONSE	RecvBuffer;
	UINT32	SendBufferSize;
	UINT32	RecvBufferSize;
	UINT16	NvPublicSize;
	UINT16	NvNameSize;
	UINT8	*Buffer;
	TPM_RC	ResponseCode;

	//
	// Construct command
	//
	SendBuffer.Header.tag = SwapBytes16(TPM_ST_NO_SESSIONS);
	SendBuffer.Header.commandCode = SwapBytes32(TPM_CC_NV_ReadPublic);

	SendBuffer.NvIndex = SwapBytes32 (NvIndex);

	SendBufferSize = (UINT32) sizeof (SendBuffer);
	SendBuffer.Header.paramSize = SwapBytes32(SendBufferSize);
	
	//
	// send Tpm command
	//
	RecvBufferSize = sizeof (RecvBuffer);
	Status = Tpm2SubmitCommand (SendBufferSize, (UINT8 *)&SendBuffer, &RecvBufferSize, (UINT8 *)&RecvBuffer);
	if (EFI_ERROR (Status)) {
		return Status;
	}
  
	if (RecvBufferSize < sizeof (TPM2_RESPONSE_HEADER)) {
		printf("Tpm2NvReadPublic - RecvBufferSize Error - %x\n", RecvBufferSize);
		return EFI_DEVICE_ERROR;
	}

	ResponseCode = SwapBytes32(RecvBuffer.Header.responseCode);
	if (ResponseCode != TPM_RC_SUCCESS) {
		printf("Tpm2NvReadPublic - responseCode - %x\n", SwapBytes32(RecvBuffer.Header.responseCode));
	}

	switch (ResponseCode) {
	case TPM_RC_SUCCESS:
		// return data
		break;
	case TPM_RC_HANDLE + RC_NV_ReadPublic_nvIndex: // TPM_RC_NV_DEFINED:
		return EFI_NOT_FOUND;
	case TPM_RC_VALUE + RC_NV_ReadPublic_nvIndex:
		return EFI_INVALID_PARAMETER;
	default:
		return EFI_DEVICE_ERROR;
	}
  
	if (RecvBufferSize <= sizeof (TPM2_RESPONSE_HEADER) + sizeof (UINT16) + sizeof(UINT16)) {
		printf("Tpm2NvReadPublic - RecvBufferSize Error - %x\n", RecvBufferSize);
		return EFI_NOT_FOUND;
	}
 
	//
	// Basic check
	//
	NvPublicSize = SwapBytes16 (RecvBuffer.NvPublic.size);
	if (NvPublicSize > sizeof(TPMS_NV_PUBLIC)) {
		printf("Tpm2NvReadPublic - NvPublic.size error %x\n", NvPublicSize);
		return EFI_DEVICE_ERROR;
	}
  
	NvNameSize = SwapBytes16(
		ReadUnaligned16 
			((UINT16 *)((UINT8 *)&RecvBuffer +
				sizeof(TPM2_RESPONSE_HEADER) +
					sizeof(UINT16) +
						NvPublicSize)));
	if (NvNameSize > sizeof(TPMU_NAME)){
		printf("Tpm2NvReadPublic - NvNameSize error %x\n", NvNameSize);
		return EFI_DEVICE_ERROR;
	}

	if (RecvBufferSize != sizeof(TPM2_RESPONSE_HEADER) + sizeof(UINT16) + NvPublicSize + sizeof(UINT16) + NvNameSize) {
		printf("Tpm2NvReadPublic - RecvBufferSize Error - NvPublicSize %x\n", RecvBufferSize);
		return EFI_NOT_FOUND;
	}
  
	//
	// Return the response
	//
	memcpy(NvPublic, &RecvBuffer.NvPublic, sizeof(UINT16) + NvPublicSize);
	NvPublic->size = NvPublicSize;
	NvPublic->nvPublic.nvIndex = SwapBytes32 (NvPublic->nvPublic.nvIndex);
	NvPublic->nvPublic.nameAlg = SwapBytes16 (NvPublic->nvPublic.nameAlg);

	WriteUnaligned32 ((UINT32 *)&NvPublic->nvPublic.attributes, SwapBytes32 (ReadUnaligned32 ((UINT32 *)&NvPublic->nvPublic.attributes)));
	NvPublic->nvPublic.authPolicy.size = SwapBytes16 (NvPublic->nvPublic.authPolicy.size);
	Buffer = (UINT8 *)&RecvBuffer.NvPublic.nvPublic.authPolicy;
	Buffer += sizeof(UINT16) + NvPublic->nvPublic.authPolicy.size;
	NvPublic->nvPublic.dataSize = SwapBytes16 (ReadUnaligned16 ((UINT16 *)Buffer));

	memcpy(NvName->name, (UINT8 *)&RecvBuffer + sizeof(TPM2_RESPONSE_HEADER) + sizeof(UINT16) + NvPublicSize + sizeof(UINT16), NvNameSize);
	NvName->size = NvNameSize;

	return EFI_SUCCESS;
}


UINT32 CopyAuthSessionCommand (
	TPMS_AUTH_COMMAND		*AuthSessionIn,
	UINT8					*AuthSessionOut
) {
	UINT8  *Buffer;

	Buffer = (UINT8 *)AuthSessionOut;

	//
	// Add in Auth session
	//
	if (AuthSessionIn != NULL) {
		//  sessionHandle
		WriteUnaligned32 ((UINT32 *)Buffer, SwapBytes32(AuthSessionIn->sessionHandle));
		Buffer += sizeof(UINT32);

		// nonce
		WriteUnaligned16 ((UINT16 *)Buffer, SwapBytes16 (AuthSessionIn->nonce.size));
		Buffer += sizeof(UINT16);

		memcpy (Buffer, AuthSessionIn->nonce.buffer, AuthSessionIn->nonce.size);
		Buffer += AuthSessionIn->nonce.size;

		// sessionAttributes
		*(UINT8 *)Buffer = *(UINT8 *)&AuthSessionIn->sessionAttributes;
		Buffer++;

		// hmac
		WriteUnaligned16 ((UINT16 *)Buffer, SwapBytes16 (AuthSessionIn->hmac.size));
		Buffer += sizeof(UINT16);

		memcpy (Buffer, AuthSessionIn->hmac.buffer, AuthSessionIn->hmac.size);
		Buffer += AuthSessionIn->hmac.size;
	} else {
		//  sessionHandle
		WriteUnaligned32 ((UINT32 *)Buffer, SwapBytes32(TPM_RS_PW));
		Buffer += sizeof(UINT32);

		// nonce = nullNonce
		WriteUnaligned16 ((UINT16 *)Buffer, SwapBytes16(0));
		Buffer += sizeof(UINT16);

		// sessionAttributes = 0
		*(UINT8 *)Buffer = 0x00;
		Buffer++;

		// hmac = nullAuth
		WriteUnaligned16 ((UINT16 *)Buffer, SwapBytes16(0));
		Buffer += sizeof(UINT16);
	}

	return (UINT32)((UINTN)Buffer - (UINTN)AuthSessionOut);
}


EFI_STATUS Tpm2NvRead (
	TPMI_RH_NV_AUTH AuthHandle,
	TPMI_RH_NV_INDEX NvIndex,
	TPMS_AUTH_COMMAND *AuthSession,
	UINT16 Size,
	UINT16 Offset,
	TPM2B_MAX_BUFFER *OutData
) {

	EFI_STATUS Status;
	TPM2_NV_READ_COMMAND SendBuffer;
	TPM2_NV_READ_RESPONSE RecvBuffer;
	UINT32 SendBufferSize;
	UINT32 RecvBufferSize;
	UINT8 *Buffer;
	UINT32 SessionInfoSize;
	TPM_RC ResponseCode;
  
	//
	// Construct command
	//
	SendBuffer.Header.tag = SwapBytes16(TPM_ST_SESSIONS);
	SendBuffer.Header.commandCode = SwapBytes32(TPM_CC_NV_Read);

	SendBuffer.AuthHandle = SwapBytes32 (AuthHandle);
	SendBuffer.NvIndex = SwapBytes32 (NvIndex);
  
	//
	// Add in Auth session
	//
	Buffer = (UINT8 *)&SendBuffer.AuthSession;

	// sessionInfoSize
	SessionInfoSize = CopyAuthSessionCommand (AuthSession, Buffer);
	Buffer += SessionInfoSize;
	SendBuffer.AuthSessionSize = SwapBytes32(SessionInfoSize);

	WriteUnaligned16 ((UINT16 *)Buffer, SwapBytes16 (Size));
	Buffer += sizeof(UINT16);
	WriteUnaligned16 ((UINT16 *)Buffer, SwapBytes16 (Offset));
	Buffer += sizeof(UINT16);

	SendBufferSize = (UINT32)(Buffer - (UINT8 *)&SendBuffer);
	SendBuffer.Header.paramSize = SwapBytes32 (SendBufferSize);

	//
	// send Tpm command
	//
	RecvBufferSize = sizeof (RecvBuffer);
	Status = Tpm2SubmitCommand (SendBufferSize, (UINT8 *)&SendBuffer, &RecvBufferSize, (UINT8 *)&RecvBuffer);
	if (EFI_ERROR (Status)) {
		goto Done;
	}	

	if (RecvBufferSize < sizeof (TPM2_RESPONSE_HEADER)) {
		printf("Tpm2NvRead - RecvBufferSize Error - %x\n", RecvBufferSize);
		Status = EFI_DEVICE_ERROR;
		goto Done;
	}
	ResponseCode = SwapBytes32(RecvBuffer.Header.responseCode);
	if (ResponseCode != TPM_RC_SUCCESS) {
		printf("Tpm2NvRead - responseCode - %x\n", ResponseCode);
	}
	switch (ResponseCode) {
	case TPM_RC_SUCCESS:
		// return data
		break;
	case TPM_RC_NV_AUTHORIZATION:
		Status = EFI_SECURITY_VIOLATION;
		break;
	case TPM_RC_NV_LOCKED:
		Status = EFI_ACCESS_DENIED;
		break;
	case TPM_RC_NV_RANGE:
		Status = EFI_BAD_BUFFER_SIZE;
		break;
	case TPM_RC_NV_UNINITIALIZED:
		Status = EFI_NOT_READY;
		break;
	case TPM_RC_HANDLE + RC_NV_Read_nvIndex: // TPM_RC_NV_DEFINED:
		Status = EFI_NOT_FOUND;
		break;
	case TPM_RC_HANDLE + RC_NV_Read_authHandle: // TPM_RC_NV_DEFINED:
		Status = EFI_INVALID_PARAMETER;
		break;
	case TPM_RC_VALUE + RC_NV_Read_nvIndex:
	case TPM_RC_VALUE + RC_NV_Read_authHandle:
		Status = EFI_INVALID_PARAMETER;
		break;
	case TPM_RC_BAD_AUTH + RC_NV_Read_authHandle + TPM_RC_S:
		Status = EFI_INVALID_PARAMETER;
		break;
	case TPM_RC_AUTH_UNAVAILABLE:
		Status = EFI_INVALID_PARAMETER;
		break;
	case TPM_RC_AUTH_FAIL + RC_NV_Read_authHandle + TPM_RC_S:
		Status = EFI_INVALID_PARAMETER;
		break;
	case TPM_RC_ATTRIBUTES + RC_NV_Read_authHandle + TPM_RC_S:
		Status = EFI_UNSUPPORTED;
		break;
	default:
		Status = EFI_DEVICE_ERROR;
		break;
	}
	if (Status != EFI_SUCCESS) {
		goto Done;
	}

	//
	// Return the response
	//
	OutData->size = SwapBytes16 (RecvBuffer.Data.size);
	if (OutData->size > MAX_DIGEST_BUFFER) {
		printf("Tpm2NvRead - OutData->size error %x\n", OutData->size);
		Status = EFI_DEVICE_ERROR;
		goto Done;
	}

	memcpy(OutData->buffer, &RecvBuffer.Data.buffer, OutData->size);

Done:
	//
	// Clear AuthSession Content
	//
	bzero (&SendBuffer, sizeof(SendBuffer));
	bzero (&RecvBuffer, sizeof(RecvBuffer));
  
	return Status;
}

