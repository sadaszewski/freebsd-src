/*-
 * SPDX-License-Identifier: BSD-4-Clause
 *
 * Copyright (c) 2021 Stanislaw R. Adaszewski
 * All rights reserved.
 *
 *	@(#)tpm2cpm.c	13.0 (Villeneuve) 11/27/21
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/syscallsubr.h>
#include <sys/proc.h>

#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/uio.h>
#include <sys/iov.h>
#include <crypto/sha2/sha256.h>
#include <sys/eventhandler.h>
#include <sys/malloc.h>
#include <geom/geom.h>
#include <geom/geom_int.h>
#include <geom/eli/g_eli.h>


static void zero_and_unset_env(const char *name) {
	char *value = kern_getenv(name);
	if (value == NULL)
		return;
	while (*value) {
		*value++ = '\0';
	}
	kern_unsetenv(name);
}


#if 0
static void g_wipe_eli_keys_consumer(struct g_consumer *cp) {
	printf("Consumer: %s\n", cp->geom->name);
}


static void g_wipe_eli_keys_provider(struct g_provider *pp) {
	printf("Provider: %s\n", pp->name);
}
#endif


static void g_eli_zero_key(struct g_eli_softc *sc, struct g_eli_key *key) {
	mtx_assert(&sc->sc_ekeys_lock, MA_OWNED);
	explicit_bzero(key, G_ELI_DATAKEYLEN);
}


static void g_eli_my_key_destroy(struct g_eli_softc *sc) {
	mtx_lock(&sc->sc_ekeys_lock);
	if ((sc->sc_flags & G_ELI_FLAG_SINGLE_KEY) != 0) {
		printf("Destroying single key!\n");
		explicit_bzero(sc->sc_ekey, sizeof(sc->sc_ekey));
	} else {
		struct g_eli_key *key;

		// printf("gek_next: 0x%x\n", TAILQ_FIRST(&sc->sc_ekeys_queue)->gek_next);

		TAILQ_FOREACH(key, &sc->sc_ekeys_queue, gek_next) {
			// printf("Destroying key: %lu!\n", key->gek_keyno);
			g_eli_zero_key(sc, key);
		}
	}
	mtx_unlock(&sc->sc_ekeys_lock);
}


static void g_wipe_eli_keys_geom(struct g_geom *gp) {
#if 0
	struct g_consumer *cp;
	struct g_provider *pp;
#endif

	printf("Wiping ELI keys for geom: %s\n", gp->name);

#if 0
	LIST_FOREACH(cp, &gp->consumer, consumer) {
		g_wipe_eli_keys_consumer(cp);
	}

	LIST_FOREACH(pp, &gp->provider, provider) {
		g_wipe_eli_keys_provider(pp);
	}
#endif

	g_eli_my_key_destroy(gp->softc);
}


static void g_wipe_eli_keys_class(struct g_class *mp) {
	struct g_geom *gp;

	if (strcmp(mp->name, G_ELI_CLASS_NAME) != 0)
		return;

	LIST_FOREACH(gp, &mp->geom, geom)
	    g_wipe_eli_keys_geom(gp);
}


static void g_wipe_eli_keys(void *p, int flag) {
	struct g_class *mp;

	KASSERT(flag != EV_CANCEL, ("g_wipe_eli_keys was cancelled"));
	g_topology_assert();

	LIST_FOREACH(mp, &g_classes, class) {
		g_wipe_eli_keys_class(mp);
	}
}


static void wipe_geli_keys() {
	g_waitfor_event(g_wipe_eli_keys, NULL, M_WAITOK, NULL);
}


static void destroy_crypto_info() {
	zero_and_unset_env("kern.geom.eli.passphrase");
	zero_and_unset_env("kern.geom.eli.passphrase.from_tpm2.passphrase");
	wipe_geli_keys();
}


static int mypanic(const char *msg) {
	const int panic_reboot_wait_time = 10;
	int loop;

	printf("%s\n", msg);
	for (loop = panic_reboot_wait_time * 10; loop > 0; --loop) {
		DELAY(1000 * 100); /* 1/10th second */
	}
	destroy_crypto_info();
	panic("%s\n", msg);
}


static void sha256_digest_make_human_readable(const unsigned char *digest, char *digest_human_readable) {
	for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		snprintf(digest_human_readable + i * 2, 3, "%02x", digest[i]);
	}
	digest_human_readable[2 * SHA256_DIGEST_LENGTH] = '\0';
}


static void tpm2_check_passphrase_marker(void *param) {
	struct thread *td = curthread;

	int error;
	struct stat sb;
	int fd;
	struct iovec aiov;
	struct uio auio;
	char buf[SHA256_DIGEST_LENGTH * 2 + 1];
	unsigned char digest[SHA256_DIGEST_LENGTH];
	char digest_human_readable[SHA256_DIGEST_LENGTH * 2 + 1];
	SHA256_CTX ctx;
	char *salt;

	char *was_retrieved = kern_getenv("kern.geom.eli.passphrase.from_tpm2.was_retrieved");
	char *passphrase = kern_getenv("kern.geom.eli.passphrase.from_tpm2.passphrase");

	if (was_retrieved == NULL || was_retrieved[0] != '1') {
		printf("Passphrase from TPM was not used - OK.\n");
		return;
	}

	if (passphrase == NULL) {
		mypanic("Passphrase was retrieved from the TPM but was not passed to us.\n");
	}

	error = kern_statat(td, 0, AT_FDCWD, "/.passphrase_marker", UIO_SYSSPACE, &sb, NULL);
	if (error) {
		mypanic("kern_statat() on passphrase marker failed");
	}

	if (sb.st_uid != 0 || (sb.st_mode & 0077)) {
		mypanic("Passphrase marker has wrong permissions set");
	}

	if (sb.st_size >= SHA256_DIGEST_LENGTH * 2 + 1) {
		mypanic("Passphrase marker too long");
	}

	error = kern_openat(td, AT_FDCWD, "/.passphrase_marker", UIO_SYSSPACE, O_RDONLY, 0);
	if (error) {
		mypanic("Cannot open the passphrase marker");
	}
	fd = td->td_retval[0];
	printf("fd: %d\n", fd);

	aiov.iov_base = &buf[0];
	aiov.iov_len = sb.st_size;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = sb.st_size;
	auio.uio_segflg = UIO_SYSSPACE;
	error = kern_readv(td, fd, &auio);
	if (error) {
		mypanic("Failed to read the passphrase marker");
	}
	buf[sb.st_size] = '\0';

	SHA256_Init(&ctx);
	salt = kern_getenv("kern.geom.eli.passphrase.from_tpm2.salt");
	printf("salt: %s, %lu\n", salt, strlen(salt));
	if (salt != NULL) {
		SHA256_Update(&ctx, salt, strlen(salt));
	}
	SHA256_Update(&ctx, passphrase, strlen(passphrase));
	SHA256_Final(digest, &ctx);
	sha256_digest_make_human_readable(digest, digest_human_readable);

	if (strncmp(buf, digest_human_readable, SHA256_DIGEST_LENGTH * 2 + 1) != 0) {
		mypanic("Passphrase marker does not match");
	}

	printf("Passphrase marker found and matching - we are done.\n");
	zero_and_unset_env("kern.geom.eli.passphrase.from_tpm2.passphrase");
	zero_and_unset_env("kern.geom.eli.passphrase");

	error = kern_close(td, fd);
	if (error) {
		printf("Failed to close passphrase marker - that's weird.\n");
	}
}


static void tpm2cpm_init(void *param) {
	EVENTHANDLER_REGISTER(mountroot, tpm2_check_passphrase_marker, NULL, EVENTHANDLER_PRI_FIRST);
}


SYSINIT(tpm2cpm_init, SI_SUB_EVENTHANDLER + 1, SI_ORDER_ANY, tpm2cpm_init, NULL);
