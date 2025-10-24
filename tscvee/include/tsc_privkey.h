/*
 * tsc_privkey.h
 * Provide a compile-time fallback private key for local testing.
 * In production, do NOT store secrets in source. Provision keys securely.
 */

#ifndef TSC_PRIVKEY_H
#define TSC_PRIVKEY_H

/* Default (insecure) private key used only for local tests */
static const char TSC_PRIVKEY[] = "default_demo_priv_key_please_replace";

#endif /* TSC_PRIVKEY_H */
