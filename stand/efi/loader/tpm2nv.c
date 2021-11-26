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


typedef struct {
	TPM2_COMMAND_HEADER	Header;
	TPMI_DH_OBJECT			TpmKey;
	TPMI_DH_ENTITY			Bind;
	TPM2B_NONCE			NonceCaller;
	TPM2B_ENCRYPTED_SECRET	Salt;
	TPM_SE					SessionType;
	TPMT_SYM_DEF			Symmetric;
	TPMI_ALG_HASH			AuthHash;
} TPM2_START_AUTH_SESSION_COMMAND;

typedef struct {
	TPM2_RESPONSE_HEADER	Header;
	TPMI_SH_AUTH_SESSION	SessionHandle;
	TPM2B_NONCE			NonceTPM;
} TPM2_START_AUTH_SESSION_RESPONSE;

typedef struct {
	TPM2_COMMAND_HEADER	Header;
	TPMI_SH_POLICY			PolicySession;
	TPM2B_DIGEST			PcrDigest;
	TPML_PCR_SELECTION		Pcrs;
} TPM2_POLICY_PCR_COMMAND;

typedef struct {
	TPM2_RESPONSE_HEADER	Header;
} TPM2_POLICY_PCR_RESPONSE;

typedef struct {
	TPM2_COMMAND_HEADER       Header;
	TPMI_RH_NV_AUTH           AuthHandle;
	TPMI_RH_NV_INDEX          NvIndex;
	UINT32                    AuthSessionSize;
	TPMS_AUTH_COMMAND         AuthSession;
} TPM2_NV_READLOCK_COMMAND;

typedef struct {
	TPM2_RESPONSE_HEADER       Header;
	UINT32                     AuthSessionSize;
	TPMS_AUTH_RESPONSE         AuthSession;
} TPM2_NV_READLOCK_RESPONSE;

#pragma pack()


static UINT16 SwapBytes16 (UINT16 Value) {
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


static UINT32 CopyAuthSessionCommand (
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

EFI_STATUS Tpm2StartAuthSession (
	TPMI_DH_OBJECT			TpmKey,
	TPMI_DH_ENTITY			Bind,
	TPM2B_NONCE			*NonceCaller,
	TPM2B_ENCRYPTED_SECRET	*Salt,
	TPM_SE					SessionType,
	TPMT_SYM_DEF			*Symmetric,
	TPMI_ALG_HASH			AuthHash,
	TPMI_SH_AUTH_SESSION	*SessionHandle,
	TPM2B_NONCE			*NonceTPM
) {
	EFI_STATUS                        Status;

	TPM2_START_AUTH_SESSION_COMMAND	SendBuffer;
	TPM2_START_AUTH_SESSION_RESPONSE	RecvBuffer;
	UINT32	SendBufferSize;
	UINT32	RecvBufferSize;
	UINT8	*Buffer;

	//
	// Construct command
	//
	SendBuffer.Header.tag = SwapBytes16(TPM_ST_NO_SESSIONS);
	SendBuffer.Header.commandCode = SwapBytes32(TPM_CC_StartAuthSession);

	SendBuffer.TpmKey = SwapBytes32 (TpmKey);
	SendBuffer.Bind = SwapBytes32 (Bind);
	Buffer = (UINT8 *)&SendBuffer.NonceCaller;

	WriteUnaligned16 ((UINT16 *)Buffer, SwapBytes16 (NonceCaller->size));
	Buffer += sizeof(UINT16);
	memcpy (Buffer, NonceCaller->buffer, NonceCaller->size);
	Buffer += NonceCaller->size;

	WriteUnaligned16 ((UINT16 *)Buffer, SwapBytes16 (Salt->size));
	Buffer += sizeof(UINT16);
	memcpy (Buffer, Salt->secret, Salt->size);
	Buffer += Salt->size;

	*(TPM_SE *)Buffer = SessionType;
	Buffer++;

	WriteUnaligned16 ((UINT16 *)Buffer, SwapBytes16 (Symmetric->algorithm));
	Buffer += sizeof(UINT16);
	switch (Symmetric->algorithm) {
	case TPM_ALG_NULL:
		break;
	case TPM_ALG_AES:
		WriteUnaligned16 ((UINT16 *)Buffer, SwapBytes16 (Symmetric->keyBits.aes));
		Buffer += sizeof(UINT16);
		WriteUnaligned16 ((UINT16 *)Buffer, SwapBytes16 (Symmetric->mode.aes));
		Buffer += sizeof(UINT16);
		break;
	case TPM_ALG_SM4:
		WriteUnaligned16 ((UINT16 *)Buffer, SwapBytes16 (Symmetric->keyBits.SM4));
		Buffer += sizeof(UINT16);
		WriteUnaligned16 ((UINT16 *)Buffer, SwapBytes16 (Symmetric->mode.SM4));
		Buffer += sizeof(UINT16);
		break;
	case TPM_ALG_SYMCIPHER:
		WriteUnaligned16 ((UINT16 *)Buffer, SwapBytes16 (Symmetric->keyBits.sym));
		Buffer += sizeof(UINT16);
		WriteUnaligned16 ((UINT16 *)Buffer, SwapBytes16 (Symmetric->mode.sym));
		Buffer += sizeof(UINT16);
		break;
	case TPM_ALG_XOR:
		WriteUnaligned16 ((UINT16 *)Buffer, SwapBytes16 (Symmetric->keyBits.xor));
		Buffer += sizeof(UINT16);
		break;
	default:
		printf("Tpm2StartAuthSession - Symmetric->algorithm - %x\n", Symmetric->algorithm);
		return EFI_UNSUPPORTED;
	}

	WriteUnaligned16 ((UINT16 *)Buffer, SwapBytes16 (AuthHash));
	Buffer += sizeof(UINT16);

	SendBufferSize = (UINT32) ((UINTN)Buffer - (UINTN)&SendBuffer);
	SendBuffer.Header.paramSize = SwapBytes32 (SendBufferSize);

	//
	// send Tpm command
	//
	RecvBufferSize = sizeof (RecvBuffer);
	Status = Tpm2SubmitCommand (SendBufferSize, (UINT8 *)&SendBuffer, &RecvBufferSize, (UINT8 *)&RecvBuffer);
	if (EFI_ERROR (Status)) {
		return Status;
	}

	if (RecvBufferSize < sizeof (TPM2_RESPONSE_HEADER)) {
		printf("Tpm2StartAuthSession - RecvBufferSize Error - %x\n", RecvBufferSize);
		return EFI_DEVICE_ERROR;
	}
	if (SwapBytes32(RecvBuffer.Header.responseCode) != TPM_RC_SUCCESS) {
		printf("Tpm2StartAuthSession - responseCode - %x\n", SwapBytes32(RecvBuffer.Header.responseCode));
		return EFI_DEVICE_ERROR;
	}

	//
	// Return the response
	//
	*SessionHandle = SwapBytes32 (RecvBuffer.SessionHandle);
	NonceTPM->size = SwapBytes16 (RecvBuffer.NonceTPM.size);
	if (NonceTPM->size > sizeof(TPMU_HA)) {
		printf("Tpm2StartAuthSession - NonceTPM->size error %x\n", NonceTPM->size);
		return EFI_DEVICE_ERROR;
	}

	memcpy(NonceTPM->buffer, &RecvBuffer.NonceTPM.buffer, NonceTPM->size);

	return EFI_SUCCESS;
}

#if 0
typedef struct {
	TPM2_COMMAND_HEADER	Header;
	TPMI_SH_POLICY			PolicySession;
	TPM2B_DIGEST			PcrDigest;
	TPML_PCR_SELECTION		Pcrs;
} TPM2_POLICY_PCR_COMMAND;

typedef struct {
	TPM2_RESPONSE_HEADER	Header;
} TPM2_POLICY_PCR_RESPONSE;
#endif


static void print_as_bytes(void *d, UINT32 size) {
	UINT8 *Buffer = (UINT8*) d;
	for (UINT32 i = 0; i < size; i++) {
		printf("0x%x ", Buffer[i]);
	}
	printf("\n");
}


static void debug_tpm2_policy_pcr_send_buffer(
	TPM2_POLICY_PCR_COMMAND	*SendBuffer,
	UINT32						SendBufferSize
) {
	printf("debug_tpm2_policy_pcr_send_buffer:\n");
	printf("Header.tag: 0x%x, should be: 0x%x\n", SwapBytes16(SendBuffer->Header.tag), TPM_ST_NO_SESSIONS);
	printf("Header.paramSize: %d, should be: %d\n", SwapBytes32(SendBuffer->Header.paramSize), SendBufferSize);
	printf("Header.commandCode: 0x%x, should be: 0x%x\n", SwapBytes32(SendBuffer->Header.commandCode), TPM_CC_PolicyPCR);
	printf("PolicySession: 0x%x\n", SwapBytes32(SendBuffer->PolicySession));
	UINT8 *Buffer = (UINT8*) &SendBuffer->PcrDigest;
	printf("PcrDigest.size: %u\n", SwapBytes16(*((UINT16*) Buffer)));
	Buffer += sizeof(UINT16);
	printf("Pcrs.count: %u\n", SwapBytes32(*((UINT32*) Buffer)));
	Buffer += sizeof(UINT32);
	TPMS_PCR_SELECTION *sel = (TPMS_PCR_SELECTION*) Buffer;
	printf("Pcrs.pcrSelections[0].hash: 0x%x, TPM_ALG_SHA256: 0x%x\n", SwapBytes16(sel->hash), TPM_ALG_SHA256);
	printf("Pcrs.pcrSelections[0].sizeofSelect: %d\n", sel->sizeofSelect);
	printf("Pcrs.pcrSelections[0].pcrSelect: "); print_as_bytes(sel->pcrSelect, sel->sizeofSelect);
	Buffer += sizeof(UINT16) + sizeof(UINT8) + sel->sizeofSelect;
	
	printf("size check: %lu, should be: %lu\n", ((UINTN) Buffer) - ((UINTN) (UINT8*) SendBuffer), (UINTN) SendBufferSize);
}


EFI_STATUS Tpm2PolicyPCR(
	TPMI_SH_POLICY		PolicySession,
	TPM2B_DIGEST		*PcrDigest,
	TPML_PCR_SELECTION	*Pcrs
) {
	EFI_STATUS					Status;
	TPM2_POLICY_PCR_COMMAND	SendBuffer;
	TPM2_POLICY_PCR_RESPONSE	RecvBuffer;
	UINT32	SendBufferSize;
	UINT32	RecvBufferSize;
	UINT8	*Buffer;

	//
	// Construct command
	//
	SendBuffer.Header.tag = SwapBytes16(TPM_ST_NO_SESSIONS);
	SendBuffer.Header.commandCode = SwapBytes32(TPM_CC_PolicyPCR);

	SendBuffer.PolicySession = SwapBytes32(PolicySession);
	Buffer = (UINT8*) &SendBuffer.PcrDigest;
	
	WriteUnaligned16 ((UINT16 *)Buffer, SwapBytes16 (PcrDigest->size));
	Buffer += sizeof(UINT16);
	memcpy (Buffer, PcrDigest->buffer, PcrDigest->size);
	Buffer += PcrDigest->size;
	
	WriteUnaligned32 ((UINT32 *)Buffer, SwapBytes32 (Pcrs->count));
	Buffer += sizeof(UINT32);
	for (UINT32 i = 0; i < Pcrs->count; i++) {
		WriteUnaligned16 ((UINT16 *)Buffer, SwapBytes16 (Pcrs->pcrSelections[i].hash));
		Buffer += sizeof(UINT16);
		(*Buffer) = Pcrs->pcrSelections[i].sizeofSelect;
		Buffer += 1;
		memcpy(Buffer, &Pcrs->pcrSelections[i].pcrSelect[0], Pcrs->pcrSelections[i].sizeofSelect);
		Buffer += Pcrs->pcrSelections[i].sizeofSelect;
	}
	
	SendBufferSize = (UINT32) ((UINTN)Buffer - (UINTN)&SendBuffer);
	SendBuffer.Header.paramSize = SwapBytes32(SendBufferSize);
	
	debug_tpm2_policy_pcr_send_buffer(&SendBuffer, SendBufferSize);
	
	//
	// send Tpm command
	//
	RecvBufferSize = sizeof (RecvBuffer);
	Status = Tpm2SubmitCommand (SendBufferSize, (UINT8 *)&SendBuffer, &RecvBufferSize, (UINT8 *)&RecvBuffer);
	if (EFI_ERROR (Status)) {
		return Status;
	}
	
	if (RecvBufferSize < sizeof (TPM2_RESPONSE_HEADER)) {
		printf("Tpm2PolicyPCR - RecvBufferSize Error - %x\n", RecvBufferSize);
		return EFI_DEVICE_ERROR;
	}
	if (SwapBytes32(RecvBuffer.Header.responseCode) != TPM_RC_SUCCESS) {
		printf("Tpm2PolicyPCR - responseCode - %x\n", SwapBytes32(RecvBuffer.Header.responseCode));
		return EFI_DEVICE_ERROR;
	}
	
	return EFI_SUCCESS;
}


EFI_STATUS Tpm2NvReadLock (
    TPMI_RH_NV_AUTH		AuthHandle,
    TPMI_RH_NV_INDEX	NvIndex,
    TPMS_AUTH_COMMAND	*AuthSession
) {
	EFI_STATUS					Status;
	TPM2_NV_READLOCK_COMMAND	SendBuffer;
	TPM2_NV_READLOCK_RESPONSE	RecvBuffer;
	UINT32		SendBufferSize;
	UINT32		RecvBufferSize;
	UINT8		*Buffer;
	UINT32		SessionInfoSize;
	TPM_RC		ResponseCode;

	//
	// Construct command
	//
	SendBuffer.Header.tag = SwapBytes16(TPM_ST_SESSIONS);
	SendBuffer.Header.commandCode = SwapBytes32(TPM_CC_NV_ReadLock);

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
		printf("Tpm2NvReadLock - RecvBufferSize Error - %x\n", RecvBufferSize);
		Status = EFI_DEVICE_ERROR;
		goto Done;
	}

	ResponseCode = SwapBytes32(RecvBuffer.Header.responseCode);
	if (ResponseCode != TPM_RC_SUCCESS) {
		printf("Tpm2NvReadLock - responseCode - %x\n", SwapBytes32(RecvBuffer.Header.responseCode));
	}
	switch (ResponseCode) {
	case TPM_RC_SUCCESS:
		// return data
		break;
	default:
		Status = EFI_DEVICE_ERROR;
		break;
	}

Done:
	//
	// Clear AuthSession Content
	//
	explicit_bzero(&SendBuffer, sizeof(SendBuffer));
	explicit_bzero(&RecvBuffer, sizeof(RecvBuffer));

	return Status;
}
