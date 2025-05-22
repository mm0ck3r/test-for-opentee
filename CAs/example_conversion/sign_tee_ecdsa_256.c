/*****************************************************************************
** Copyright (C) 2022 Technology Innovation Institute (TII)                 **
**                                                                          **
** Licensed under the Apache License, Version 2.0 (the "License");          **
** you may not use this file except in compliance with the License.         **
** You may obtain a copy of the License at                                  **
**                                                                          **
**      http://www.apache.org/licenses/LICENSE-2.0                          **
**                                                                          **
** Unless required by applicable law or agreed to in writing, software      **
** distributed under the License is distributed on an "AS IS" BASIS,        **
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. **
** See the License for the specific language governing permissions and      **
** limitations under the License.                                           **
*****************************************************************************/

/* Simple application for testing entry point functions calling.
 * Application will be updated as manager process development goes forward */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tee_client_api.h"
#include "sign_ecdsa_256_ctrl.h"

/* Data buffer sizes */
#define DATA_SIZE   256
#define SHA1_SIZE   20
#define SHA256_SIZE 32

/* Hash TA command IDs for this applet */
#define HASH_DO_FINAL 0x00000001
#define SIGN_DO_FINAL   0x00000002

/* Hash algoithm */
#define HASH_MD5   0x00000001
#define HASH_SHA1   0x00000002
#define HASH_SHA224   0x00000003
#define HASH_SHA256   0x00000004
#define HASH_SHA384   0x00000005
#define HASH_SHA512   0x00000006

/* Blockchain Network */
#define NETWORK_BITCOIN 0x0
#define NETWORK_ETHEREUM 0x1
#define DUMP_KEY 0xDEAD
/* Message */
#define BITCOIN_MESSAGE "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"
#define BITCOIN_MESSAGE_LEN 32

void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

int main()
{
   TEEC_Context context;
   TEEC_Session session;
   TEEC_Operation operation = {0};
   TEEC_SharedMemory in_mem = {0};
   TEEC_SharedMemory out_mem = {0};
   TEEC_SharedMemory sign_input_mem = {0};
   TEEC_SharedMemory sign_output_mem = {0};
   TEEC_SharedMemory key = {0};
   TEEC_Result tee_rv;

   char data[DATA_SIZE];
   uint8_t sha256[SHA256_SIZE];
   unsigned char sig[72];
   uint8_t fuck[96];

   int i;
   
   printf("\nSTART: example ECDSA for BITCOIN app\n");

   /* Initialize data stuctures */
   memset((void *)&in_mem, 0, sizeof(in_mem));
   memset((void *)&out_mem, 0, sizeof(out_mem));
   memset((void *)&operation, 0, sizeof(operation));
   strncpy(data, BITCOIN_MESSAGE, BITCOIN_MESSAGE_LEN);
   memset(sha256, 0, SHA256_SIZE);
   memset(sig, 0, 72);

   /*
    * Initialize context towards TEE
    */
   printf("Initializing context: ");
   tee_rv = TEEC_InitializeContext(NULL, &context);
   if (tee_rv != TEEC_SUCCESS) {
      printf("TEEC_InitializeContext failed: 0x%x\n", tee_rv);
      goto end_1;
   } else {
      printf("initialized\n");
   }

   /*
    * Open session towards Digest TA
    */
   tee_rv = TEEC_OpenSession(&context, &session,
              &uuid, TEEC_LOGIN_PUBLIC,
              NULL, NULL, NULL);
   if (tee_rv != TEEC_SUCCESS) {
      printf("TEEC_OpenSession failed: 0x%x\n", tee_rv);
      goto end_2;
   }


   ///////////////////
   ///// Hashing /////
   ///////////////////
   in_mem.buffer = data;
   in_mem.size = BITCOIN_MESSAGE_LEN;
   in_mem.flags = TEEC_MEM_INPUT;

   tee_rv = TEEC_RegisterSharedMemory(&context, &in_mem);
   if (tee_rv != TEE_SUCCESS) {
      printf("Failed to register IN shared memory\n");
      goto end_3;
   }

   out_mem.buffer = sha256;
   out_mem.size = SHA256_SIZE;
   out_mem.flags = TEEC_MEM_OUTPUT;

   tee_rv = TEEC_RegisterSharedMemory(&context, &out_mem);
   if (tee_rv != TEE_SUCCESS) {
      printf("Failed to allocate OUT shared memory\n");
      goto end_3;
   }

   operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_WHOLE,
                  TEEC_MEMREF_WHOLE, TEEC_NONE);
   operation.params[0].value.a = NETWORK_BITCOIN;
   operation.params[1].memref.parent = &in_mem;
   operation.params[2].memref.parent = &out_mem;

   printf("Invoking command: Do final Double sha256: ");
   tee_rv = TEEC_InvokeCommand(&session, HASH_DO_FINAL, &operation, NULL);
   if (tee_rv != TEEC_SUCCESS) {
      printf("Hash TEEC_InvokeCommand failed: 0x%x\n", tee_rv);
      goto end_4;
   } else {
      printf("Hash Done\n");
   }

   /*
    * Printf sha256 buf
    */
   printf("Calculated sha256: ");
   for (i = 0; i < SHA256_SIZE; i++)
      printf("%02x", sha256[i]);
   printf("\n");


   ///////////////////
   ///// Signing /////
   ///////////////////
   sign_input_mem.buffer = sha256;
   sign_input_mem.size = SHA256_SIZE;
   sign_input_mem.flags = TEEC_MEM_INPUT;

   tee_rv = TEEC_RegisterSharedMemory(&context, &sign_input_mem);
   if (tee_rv != TEEC_SUCCESS) {
      printf("Failed to register IN shared memory for signing\n");
      goto end_4;
   }

   sign_output_mem.buffer = sig;
   sign_output_mem.size = sizeof(sig);
   sign_output_mem.flags = TEEC_MEM_OUTPUT;

   tee_rv = TEEC_RegisterSharedMemory(&context, &sign_output_mem);
   if (tee_rv != TEEC_SUCCESS) {
      printf("Failed to register OUT shared memory for signature\n");
      goto end_4;
   }
   

   operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_WHOLE,
                  TEEC_MEMREF_WHOLE, TEEC_NONE);
   operation.params[0].value.a = NETWORK_BITCOIN;
   operation.params[1].memref.parent = &sign_input_mem;
   operation.params[2].memref.parent = &sign_output_mem;
   tee_rv = TEEC_InvokeCommand(&session, SIGN_DO_FINAL, &operation, NULL);
   if (tee_rv != TEEC_SUCCESS) {
      printf("Sign TEEC_InvokeCommand failed: 0x%x\n", tee_rv);
      goto end_4;
   }

   // Signature 출력
   printf("Signature: ");
   for (i = 0; i < sign_output_mem.size; i++) {
      printf("%02x", sig[i]);
   }
   printf("\n");

   // 개인키, 공개키 출력

   // key.buffer = fuck;
   // key.size = sizeof(fuck);
   // key.flags = TEEC_MEM_OUTPUT;

    // tee_rv = TEEC_RegisterSharedMemory(&context, &key);
    // if (tee_rv != TEEC_SUCCESS) {
    //     printf("Shared memory alloc failed: 0x%x\n", tee_rv);
    //     goto end_1;
    // }

   // memset((void *)&operation, 0, sizeof(operation));

   // operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    // operation.params[0].memref.parent = &key;
    // operation.params[0].memref.size = key.size;

   // tee_rv = TEEC_InvokeCommand(&session, DUMP_KEY, &operation, NULL);
    // if (tee_rv != TEEC_SUCCESS) {
    //     printf("Invoke failed: 0x%x\n", tee_rv);
    //     goto end_1;
    // }

   // print_hex("Private d", key.buffer, 32);
    // print_hex("Public X", (uint8_t *)key.buffer + 32, 32);
    // print_hex("Public Y", (uint8_t *)key.buffer + 64, 32);


   
end_4:
   TEEC_ReleaseSharedMemory(&out_mem);

end_3:
   TEEC_ReleaseSharedMemory(&in_mem);
   TEEC_CloseSession(&session);
end_2:
   TEEC_FinalizeContext(&context);
end_1:
   exit(tee_rv);
}