#ifndef _EFITPM2_H_
#define _EFITPM2_H_

#include <efi.h>

EFI_STATUS tpm2_init();
EFI_STATUS tpm2_geli_passphrase_from_efivar();
void tpm2_try_autoboot_or_clear_geli_keys();
void tpm2_check_efivars();
void tpm2_retrieve_passphrase();
void tpm2_check_passphrase_marker();

#endif

