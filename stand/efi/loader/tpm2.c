#include "efitpm2.h"
#include "efitpm2nv.h"

#include <efi.h>
#include <efilib.h>
#include <efichar.h>

#include <Protocol/Tcg2Protocol.h>

static EFI_GUID tcg2_protocol = EFI_TCG2_PROTOCOL_GUID;
static EFI_TCG2_PROTOCOL *tcg2 = NULL;


TPMI_ALG_HASH tpm2_parse_efivar_policy_spec(BYTE *pcrSelect, BYTE *sizeofSelect);


EFI_STATUS tpm2_init() {
	EFI_STATUS status;
	
	printf("Trying to locate TCG2 protocol...\n");
	status = BS->LocateProtocol(&tcg2_protocol, NULL, (VOID **)&tcg2);

	if (status != EFI_SUCCESS) {
		printf("Failed to locate TCG2 protocol.\n");
		BS->Exit(IH, status, 0, NULL);
	}
	
	printf("Successfully located TCG2 protocol.\n");
	
	printf("NV_INDEX_FIRST: 0x%x\n", NV_INDEX_FIRST);
	printf("NV_INDEX_LAST: 0x%x\n", NV_INDEX_LAST);

	for (int i = 0; i < 3; i++) {
		TPMI_RH_NV_INDEX NvIndex = 0x1000001;
		TPM2B_NV_PUBLIC NvPublic;
		TPM2B_NAME NvName;
		
		status = Tpm2NvReadPublic (NvIndex, &NvPublic, &NvName);
		if (status != EFI_SUCCESS) {
			printf("Failed to read public NV at index 0x%x.\n", NvIndex);
		} else {
			printf("Read name: %.*s\n", NvName.size, NvName.name);
		}

	}
	
	printf("Trying Tpm2StartAuthSession...\n");
	TPM2B_DIGEST NonceCaller = { 16 };
	TPM2B_ENCRYPTED_SECRET Salt = { 0 };
	TPMT_SYM_DEF Symmetric = { TPM_ALG_NULL };
	TPMI_SH_AUTH_SESSION SessionHandle;
	TPM2B_NONCE NonceTPM;
	status = Tpm2StartAuthSession (
		TPM_RH_NULL,	// TpmKey
		TPM_RH_NULL,	// Bind
		&NonceCaller,
		&Salt,
		TPM_SE_POLICY,	// SessionType
		&Symmetric,
		TPM_ALG_SHA256,	//AuthHash
		&SessionHandle,
		&NonceTPM
	);
	printf("status: 0x%lx\n", status);
	printf("SessionHandle: 0x%x\n", SessionHandle);
	printf("NonceTPM.size: %d\n", NonceTPM.size);
	
	printf("Trying Tpm2PolicyPCR...\n");
	TPM2B_DIGEST PcrDigest = { .size = 0 };
	TPML_PCR_SELECTION Pcrs = {
		.count = 1,
		.pcrSelections = {
			{
				.hash = TPM_ALG_SHA256,
				.sizeofSelect = PCR_SELECT_MIN,
	            .pcrSelect = { (1 << 0) | (1 << 2) }
			}
		}
	};
	status = Tpm2PolicyPCR(
		SessionHandle, 	// PolicySession
		&PcrDigest,
		&Pcrs
	);
	printf("status: 0x%lx\n", status);

	BYTE pcrSelect[PCR_SELECT_MAX];
	BYTE sizeofSelect;
	TPMI_ALG_HASH alg = tpm2_parse_efivar_policy_spec(pcrSelect, &sizeofSelect);
	printf("alg: 0x%x, sizeofSelect: %d, pcrSelect: 0x%x 0x%x 0x%x\n",
	    alg, sizeofSelect, pcrSelect[0], pcrSelect[1], pcrSelect[2]);

	do {
		printf("Trying to actually read a PCR-policy protected NVindex...\n");
		TPM2B_MAX_BUFFER OutData = { 0 };
		TPMS_AUTH_COMMAND AuthSession = {
		    .sessionHandle = SessionHandle,
		    .nonce = { 0 },
		    .sessionAttributes = 0,
		    .hmac = { 0 }
		};
		status = Tpm2NvRead(SessionHandle, 0x1000001, &AuthSession, 12, 0, &OutData);
		printf("status: 0x%lx\n", status);
		OutData.buffer[12] = '\0';
		printf("OutData.size: %u\n", OutData.size);
		printf("OutData.buffer: %s\n", OutData.buffer);

	} while (0);
	
	time_t now;
	time_t then = getsecs();
	do {
		now = getsecs();
	} while (now - then < 10);
	
	return EFI_SUCCESS;
}


EFI_STATUS tpm2_geli_passphrase_from_efivar() {
	const char *name = "KernGeomEliPassphrase";
	char *freeme = NULL;
	UINTN len = 0;
	EFI_STATUS status;
	
	if (efi_freebsd_getenv(name, NULL, &len) == EFI_BUFFER_TOO_SMALL) {
		freeme = malloc(len + 1);
		if (freeme == NULL)
			return (status = EFI_OUT_OF_RESOURCES);
		if (efi_freebsd_getenv(name, freeme, &len) == EFI_SUCCESS) {
			freeme[len] = '\0';
			setenv("kern.geom.eli.passphrase", freeme, 1);
			status = EFI_SUCCESS;
		} else {
			status = EFI_DEVICE_ERROR;
		}
		(void)free(freeme);
	} else {
		status = EFI_NOT_FOUND;
	}
	
	return status;
}


static char *efi_freebsd_getenv_helper(const char *name) {
	char *freeme = NULL;
	UINTN len = 0;

	if (efi_freebsd_getenv(name, NULL, &len) == EFI_BUFFER_TOO_SMALL) {
		freeme = malloc(len + 1);
		if (freeme == NULL)
			return NULL;
		if (efi_freebsd_getenv(name, freeme, &len) == EFI_SUCCESS) {
			freeme[len] = '\0';
			return freeme;
		} else {
			(void)free(freeme);
			return NULL;
		}
	}

	return NULL;
}


static TPMI_ALG_HASH resolve_hash_alg_name(const char *name) {
	if (strcasecmp(name, "sha1") == 0)
		return TPM_ALG_SHA1;
	else if (strcasecmp(name, "sha256") == 0)
		return TPM_ALG_SHA256;
	else if (strcasecmp(name, "sha384") == 0)
		return TPM_ALG_SHA384;
	else if (strcasecmp(name, "sha512") == 0)
		return TPM_ALG_SHA512;
	else
		return (TPMI_ALG_HASH) strtol(name, NULL, 16);
}


TPMI_ALG_HASH tpm2_parse_efivar_policy_spec(BYTE *pcrSelect, BYTE *sizeofSelect) {
	char *policy_pcr = NULL;
	char *p;
	char *pi;
	char ch;
	UINT32 pcr_index;
	TPMI_ALG_HASH alg;

	bzero(pcrSelect, PCR_SELECT_MAX);
	*sizeofSelect = PCR_SELECT_MIN;

	policy_pcr = efi_freebsd_getenv_helper("KernGeomEliPassphraseFromTpm2PolicyPcr");
	if (policy_pcr == NULL)
		return TPM_ALG_ERROR;

	setenv("kern.geom.eli.passphrase.from_tpm2.policy_pcr", policy_pcr, 1);

	p = policy_pcr;
	while (isspace(*p)) {
		p++;
	}
	pi = p;
	while (1) {
		ch = *pi;
		if (ch == ':') {
			*pi = '\0';
			if (strchr(p, ' ') != NULL)
				*strchr(p, ' ') = '\0';
			alg = resolve_hash_alg_name(p);
			p = pi + 1;
		} else if (ch == ',' || ch == '\0') {
			*pi = '\0';
			pcr_index = strtol(p, NULL, 10);
			pcrSelect[(pcr_index / 8)] |= (1 << (pcr_index % 8));
			if (1 + pcr_index / 8 > *sizeofSelect) {
				*sizeofSelect = 1 + pcr_index / 8;
			}
			p = pi + 1;
		}
		if (ch == '\0') {
			break;
		}
		pi++;
	}

	(void)free(policy_pcr);

	return alg;
}
