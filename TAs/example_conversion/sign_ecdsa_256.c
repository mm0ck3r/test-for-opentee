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

/* NOTE!!
 *
 * This is an example. It might not have the most perfect design choices and implementation.
 * It is servinc purpose of showing how you could do the most simplest SHAXXX/MD5 hash
 *
 * NOTE!!
 */

#include "tee_internal_api.h"
#include "tee_logging.h"
#include <stdio.h>
#include "sign_ecdsa_256_ctrl.h"

#ifdef TA_PLUGIN
#include "tee_ta_properties.h" /* Setting TA properties */

/* Hash TA command IDs for this applet */
#define HASH_DO_FINAL 0x00000001
#define SIGN_DO_FINAL   0x00000002
#define VERIFY_SIGNATURE 0XDEAD
/* Blockchain Network */
#define NETWORK_BITCOIN 0x0
#define NETWORK_ETHEREUM 0x1

SET_TA_PROPERTIES(
   { 0x12345678, 0x8765, 0x4321, { 'S', 'I', 'G', 'N', 'S', 'I', 'G', 'N'} }, /* UUID */
      512, /* dataSize */
      255, /* stackSize */
      1, /* singletonInstance */
      1, /* multiSession */
      1) /* instanceKeepAlive */
#endif

#define DUMP_KEY 0XDEAD


void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

TEE_Result TA_EXPORT TA_CreateEntryPoint(void)
{
   char objID[] = "signkey";
   uint32_t objID_len = 7;
   TEE_ObjectHandle signkey = NULL;
   TEE_Result rv = TEE_ERROR_GENERIC;
   TEE_Attribute params = {0};
   TEE_OperationHandle sign_operation = NULL;

   OT_LOG(LOG_ERR, "Calling the create entry point");
   
   rv = TEE_AllocateTransientObject(TEE_TYPE_ECDSA_KEYPAIR, 256, &signkey);
   if (rv != TEE_SUCCESS) {
      OT_LOG(LOG_ERR, "Transient object alloc failed [0x%x]", rv);
      goto out;
   }
   
   params.attributeID = TEE_ATTR_ECC_CURVE;
   params.content.value.a = TEE_ECC_CURVE_NIST_P256;
   
   rv = TEE_GenerateKey(signkey, 256, &params, 1);
   if (rv != TEE_SUCCESS) {
      OT_LOG(LOG_ERR, "Key generation failed [0x%x]", rv);
      goto out;
   }

   // PrintOut private key
   uint8_t privkey[32];
    size_t len = sizeof(privkey);
   rv = TEE_GetObjectBufferAttribute(signkey, TEE_ATTR_ECC_PRIVATE_VALUE, privkey, &len);
    if (rv == TEE_SUCCESS) {
        OT_LOG(LOG_ERR, "Private key: ");
        for (int i = 0; i < len; i++)
            OT_LOG(LOG_ERR, "%02x", privkey[i]);
      OT_LOG(LOG_ERR, "\n");
    } else {
        OT_LOG(LOG_ERR, "Failed to get private key: 0x%x", rv);
      goto out;
    }

   print_hex("Private Key: ", privkey, 32);

   // 공개키 X, Y 추출
   uint8_t pubkey_x[32], pubkey_y[32];
   size_t x_len = sizeof(pubkey_x), y_len = sizeof(pubkey_y);

   rv = TEE_GetObjectBufferAttribute(signkey, TEE_ATTR_ECC_PUBLIC_VALUE_X, pubkey_x, &x_len);
   if (rv != TEE_SUCCESS) {
      OT_LOG(LOG_ERR, "Failed to get public key X: 0x%x", rv);
      goto out;
   }

   rv = TEE_GetObjectBufferAttribute(signkey, TEE_ATTR_ECC_PUBLIC_VALUE_Y, pubkey_y, &y_len);
   if (rv != TEE_SUCCESS) {
      OT_LOG(LOG_ERR, "Failed to get public key Y: 0x%x", rv);
      goto out;
   }

   printf("Public key X: ");
   for (int i = 0; i < x_len; i++)
      printf("%02x", pubkey_x[i]);
   printf("\n");

   printf("Public key Y: ");
   for (int i = 0; i < y_len; i++)
      printf("%02x", pubkey_y[i]);
   printf("\n");
   
   rv = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
               objID, objID_len,
               TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_EXCLUSIVE,
               signkey,
               NULL, 0, NULL);
   if (rv != TEE_SUCCESS) {
      OT_LOG(LOG_ERR, "Persistent object create failed [0x%x]", rv);
      goto out;
   }
         
   rv = TEE_AllocateOperation(&sign_operation,
               TEE_ALG_ECDSA_SHA256, TEE_MODE_SIGN, 256);
   if (rv != TEE_SUCCESS) {
      OT_LOG(LOG_ERR, "Operation allocation failed [0x%x]", rv);
      goto out;
   }

   rv = TEE_SetOperationKey(sign_operation, signkey);
   if (rv != TEE_SUCCESS) {
      OT_LOG(LOG_ERR, "Operation key set failed [0x%x]", rv);
      goto out;
   }

   TEE_SetInstanceData(sign_operation);
   
 out:
   if (rv != TEE_SUCCESS)
      TEE_FreeOperation(sign_operation);
   TEE_FreeTransientObject(signkey);
   return rv;
}

void TA_EXPORT TA_DestroyEntryPoint(void)
{
   TEE_FreeOperation(TEE_GetInstanceData());
}

TEE_Result TA_EXPORT TA_OpenSessionEntryPoint(uint32_t paramTypes,
                     TEE_Param params[4],
                     void **sessionContext)
{
   paramTypes = paramTypes;
   params = params;
   sessionContext = sessionContext;
   
   return TEE_SUCCESS;
}

void TA_EXPORT TA_CloseSessionEntryPoint(void *sessionContext)
{
   sessionContext = sessionContext;
}

TEE_Result TA_EXPORT TA_InvokeCommandEntryPoint(void *sessionContext,
                  uint32_t commandID,
                  uint32_t paramTypes,
                  TEE_Param params[4])
{
   TEE_Result tee_rv = TEEC_SUCCESS;

   sessionContext = sessionContext;

   TEE_OperationHandle op;
   uint8_t temp_hash[32];
   size_t temp_len = sizeof(temp_hash);
   uint8_t d[32], x[32], y[32];
   uint32_t d_len = 32;
   uint32_t x_len = 32;
   uint32_t y_len = 32;

   TEE_ObjectHandle signkey = NULL;

   switch (commandID) {
      case HASH_DO_FINAL:
         switch (params[0].value.a) {
            case NETWORK_BITCOIN:{

               TEE_OperationHandle op = NULL;
               uint8_t first_hash[32];
               size_t first_hash_len = sizeof(first_hash);

               // 1차 해시
               tee_rv = TEE_AllocateOperation(&op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
               if (tee_rv != TEE_SUCCESS) {
                  OT_LOG(LOG_ERR, "[NETWORK_BITCOIN] TEE_AllocateOperation failed [0x%x]", tee_rv);
                  goto out;
               }

               tee_rv = TEE_DigestDoFinal(op,
                                    params[1].memref.buffer, params[1].memref.size,
                                    first_hash, &first_hash_len);
               if (tee_rv != TEE_SUCCESS) {
                  OT_LOG(LOG_ERR, "[NETWORK_BITCOIN] First TEE_DigestDoFinal failed [0x%x]", tee_rv);
                  goto out;
               }

               TEE_FreeOperation(op);
               // 2차 해시
               tee_rv = TEE_AllocateOperation(&op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
               if (tee_rv != TEE_SUCCESS) {
                  OT_LOG(LOG_ERR, "[NETWORK_BITCOIN] Second TEE_AllocateOperation failed [0x%x]", tee_rv);
                  goto out;
               }

               tee_rv = TEE_DigestDoFinal(op,
                                    first_hash, first_hash_len,
                                    params[2].memref.buffer, &params[2].memref.size);
               if (tee_rv != TEE_SUCCESS) {
                  OT_LOG(LOG_ERR, "[NETWORK_BITCOIN] Second TEE_DigestDoFinal failed [0x%x]", tee_rv);
                  goto out;
               }

               TEE_FreeOperation(op);
               
               break;
            }
            case NETWORK_ETHEREUM:
               break;
         default:
            break;
      }
      break;
   case SIGN_DO_FINAL:
      switch (params[0].value.a) {
         case NETWORK_BITCOIN:
            tee_rv = TEE_AsymmetricSignDigest(TEE_GetInstanceData(), NULL, 0,
                     params[1].memref.buffer, params[1].memref.size,
                     params[2].memref.buffer, &params[2].memref.size);
            if (tee_rv != TEE_SUCCESS) {
               OT_LOG(LOG_ERR, "Sign failed");
               goto out;
            }
            break;
         case NETWORK_ETHEREUM:
            break;
         default:
            break;
      }
      break;
   default:
      tee_rv = TEE_ERROR_BAD_PARAMETERS;
   }

 out:
   return tee_rv;
}
