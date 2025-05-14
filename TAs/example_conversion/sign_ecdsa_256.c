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

#include "sign_ecdsa_256_ctrl.h"

/*Modify*/
#define BitCoin 0x1

#ifdef TA_PLUGIN
#include "tee_ta_properties.h" /* Setting TA properties */

SET_TA_PROPERTIES(
	{ 0x12345678, 0x8765, 0x4321, { 'S', 'I', 'G', 'N', 'S', 'I', 'G', 'N'} }, /* UUID */
		512, /* dataSize */
		255, /* stackSize */
		1, /* singletonInstance */
		1, /* multiSession */
		1) /* instanceKeepAlive */
#endif

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
	TEE_Result rv = TEE_ERROR_GENERIC;

	sessionContext = sessionContext;

	if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_MEMREF_INPUT ||
	    TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_MEMREF_INPUT ||
		TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_MEMREF_OUTPUT) {
		OT_LOG(LOG_ERR, "Bad parameter at index 0 OR 1 OR 2");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if(commandID == SIGN_ECDSA_256_SIGN) {
		// [1] net 추출
		uint32_t network_id = *((uint32_t *)params[0].memref.buffer);

		// [2] msg 추출
		uint8_t *message = (uint8_t *)params[1].memref.buffer;
    	size_t msg_len = params[1].memref.size;

		// [3] format 처리
		uint8_t *formatted = NULL;
    	size_t formatted_len = 0;

		if(network_id == BitCoin){
			// "\x18Bitcoin Signed Message:\n" + varint(msg_len) + message
			const char prefix[] = "\x18Bitcoin Signed Message:\n";
        	size_t prefix_len = sizeof(prefix) - 1;

			// 1byte보다 작은 경우 1로 만들기 위해서...
			uint8_t varint_len = (uint8_t)msg_len;

			formatted_len = prefix_len + 1 + msg_len;
			formatted = TEE_Malloc(formatted_len, 0);
			if(!formatted){
				return TEE_ERROR_OUT_OF_MEMORY;
			}

			TEE_MemMove(formatted, (void *)prefix, prefix_len);
			formatted[prefix_len] = varint_len;
			TEE_MemMove(formatted + prefix_len + 1, message, msg_len);

			// [4] twice sha256
			uint8_t digest[32];
			size_t digest_len = 32;
    		TEE_OperationHandle sha_op = NULL;
    		rv = TEE_AllocateOperation(&sha_op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
			if (rv == TEE_SUCCESS) {
    			rv = TEE_DigestDoFinal(sha_op, formatted, formatted_len, digest, &digest_len);
    			TEE_FreeOperation(sha_op);
    			sha_op = NULL;
			}

			if (rv == TEE_SUCCESS) {
    			digest_len = 32;
    			rv = TEE_AllocateOperation(&sha_op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    			if (rv == TEE_SUCCESS) {
        			rv = TEE_DigestDoFinal(sha_op, digest, 32, digest, &digest_len);
        			TEE_FreeOperation(sha_op);
        			sha_op = NULL;
    			}
			}

			// [5] ECDSA 서명
			rv = TEE_AsymmetricSignDigest(TEE_GetInstanceData(), NULL, 0, digest, 32, params[2].memref.buffer, &params[2].memref.size);
			if (rv != TEE_SUCCESS) {
				OT_LOG(LOG_ERR, "Sign failed");
			}
			return rv;
		}
		else{
			return TEE_ERROR_BAD_PARAMETERS;
		}
	}
	else
	{
		rv = TEE_ERROR_BAD_PARAMETERS;
		return rv;
	}
}
