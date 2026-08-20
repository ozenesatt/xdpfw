/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BANNER_H
#define __BANNER_H

#include <stdio.h>
#include <unistd.h>

#define C_SIFIRLA  "\033[0m"
#define C_KALIN    "\033[1m"
#define C_SOLUK    "\033[2m"
#define C_KIRMIZI  "\033[91m"
#define C_KOYUKIRM "\033[31m"
#define C_YESIL    "\033[92m"
#define C_SARI     "\033[93m"
#define C_MAVI     "\033[94m"
#define C_BEYAZ    "\033[97m"
#define C_GRI      "\033[90m"

/* Terminal degilse renk kullanma (pipe, dosyaya yonlendirme) */
static inline int renk_var(void)
{
	return isatty(STDOUT_FILENO);
}

#define R(kod) (renk_var() ? (kod) : "")

static inline void banner_bas(void)
{
	const char *M = R(C_MAVI), *B = R(C_BEYAZ), *K = R(C_KIRMIZI);
	const char *S = R(C_SIFIRLA), *KL = R(C_KALIN), *G = R(C_GRI);
	const char *KK = R(C_KOYUKIRM);

	printf("\n");
	printf(" %s%s██╗  ██╗%s%s████████╗ █████╗ ██╗     ███████╗███╗   ██╗████████╗%s\n", KL, M, S, B, S);
	printf(" %s%s██║  ██║%s%s╚══██╔══╝██╔══██╗██║     ██╔════╝████╗  ██║╚══██╔══╝%s\n", KL, M, S, B, S);
	printf(" %s%s███████║%s%s   ██║   ███████║██║     █████╗  ██╔██╗ ██║   ██║   %s\n", KL, M, S, B, S);
	printf(" %s%s██╔══██║%s%s   ██║   ██╔══██║██║     ██╔══╝  ██║╚██╗██║   ██║   %s\n", KL, M, S, B, S);
	printf(" %s%s██║  ██║%s%s   ██║   ██║  ██║███████╗███████╗██║ ╚████║   ██║   %s\n", KL, M, S, B, S);
	printf(" %s%s╚═╝  ╚═╝%s%s   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   %s\n", KL, M, S, B, S);
	printf(" %s%s──────────────────────────────────────────────────────────%s\n", KL, KK, S);
	printf("\n");
	printf("   %s%s██╗  ██╗██████╗ ██████╗ ███████╗██╗    ██╗%s\n", KL, K, S);
	printf("   %s%s╚██╗██╔╝██╔══██╗██╔══██╗██╔════╝██║    ██║%s\n", KL, K, S);
	printf("   %s%s ╚███╔╝ ██║  ██║██████╔╝█████╗  ██║ █╗ ██║%s\n", KL, K, S);
	printf("   %s%s ██╔██╗ ██║  ██║██╔═══╝ ██╔══╝  ██║███╗██║%s\n", KL, K, S);
	printf("   %s%s██╔╝ ██╗██████╔╝██║     ██║     ╚███╔███╔╝%s\n", KL, K, S);
	printf("   %s%s╚═╝  ╚═╝╚═════╝ ╚═╝     ╚═╝      ╚══╝╚══╝ %s\n", B, S, S);
	printf("\n");
	printf(" %sXDP tabanli ag trafik izleyici ve firewall%s\n", G, S);
	printf(" %sHTalent staj projesi%s\n", G, S);
	printf("\n");
}

#endif /* __BANNER_H */
