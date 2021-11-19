#include <efi.h>
#include <efilib.h>
#include <efichar.h>

#include <IndustryStandard/Tpm20.h>
#include <Protocol/Tcg2Protocol.h>


#define RC_NV_ReadPublic_nvIndex            (TPM_RC_H + TPM_RC_1)


typedef struct {
	TPM2_COMMAND_HEADER	Header;
	TPMI_RH_NV_INDEX		NvIndex;
} TPM2_NV_READPUBLIC_COMMAND;


typedef struct {
	TPM2_RESPONSE_HEADER	Header;
	TPM2B_NV_PUBLIC			NvPublic;
	TPM2B_NAME				NvName;
} TPM2_NV_READPUBLIC_RESPONSE;


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
		printf("Buffer is NULL in ReadUnaligned16");
		BS->Exit(IH, EFI_INVALID_PARAMETER, 0, NULL);
		return ((UINT16) -1);
	}
	return *Buffer;
}


static UINT32 ReadUnaligned32 (const UINT32 *Buffer) {
 	if (Buffer == NULL) {
		printf("Buffer is NULL in ReadUnaligned32");
		BS->Exit(IH, EFI_INVALID_PARAMETER, 0, NULL);
		return ((UINT32) -1);
	}
	return *Buffer;
}


static UINT32 WriteUnaligned32 (UINT32 *Buffer, UINT32 Value) {
	if (Buffer == NULL) {
		printf("Buffer is NULL in WriteUnaligned32");
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
