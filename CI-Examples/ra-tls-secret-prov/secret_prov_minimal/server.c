/* Copyright (C) 2023 Gramine contributors
 * SPDX-License-Identifier: BSD-3-Clause */

#include <stdio.h>

#include "secret_prov.h"

#define PORT "4433"
#define SRV_CRT_PATH "../ssl/server.crt"//include the path to the etc/kii and store it in filepath 1 and 2
#define SRV_KEY_PATH "../ssl/server.key"

int main(void) {
    uint8_t secret[] = "A_SIMPLE_SECRET";
    puts("--- Starting the Secret Provisioning server on port " PORT " ---");
    int ret = secret_provision_start_server(secret, sizeof(secret),
                                            PORT, SRV_CRT_PATH, SRV_KEY_PATH,
                                            NULL, NULL);
    if (ret < 0) {
        fprintf(stderr, "[error] secret_provision_start_server() returned %d\n", ret);
        return 1;
    }
    return 0;
}
