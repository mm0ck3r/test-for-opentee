#include "tee_internal_api.h"
#include "tee_logging.h"

#include "sign_blockchain_ctrl.h"

#ifdef TA_PLUGIN
#include "tee_ta_properties.h" /* Setting TA properties */

SET_TA_PROPERTIES(
	{ 0x12345678, 0x8765, 0x4321, { 'S', 'I', 'G', 'N', 'B', 'L', 'C', 'K'} }, /* UUID */
		512, /* dataSize */
		255, /* stackSize */
		1, /* singletonInstance */
		1, /* multiSession */
		1) /* instanceKeepAlive */
#endif

#define HASH_SHA256	0x00000004

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
	sessionContext = sessionContext;
    TEE_AllocateOperation((TEE_OperationHandle *)sessionContext,
				     HASH_SHA256, TEE_MODE_DIGEST, 0);
	
	return TEE_SUCCESS;
}

void TA_EXPORT TA_CloseSessionEntryPoint(void *sessionContext)
{
	sessionContext = sessionContext;
}

TEE_Result doubleHash(void *sessionContext, TEE_Param params[4]){
    TEE_DigestUpdate(sessionContext, params[1].memref.buffer, params[1].memref.size);

    TEE_Result tee_rv = TEE_SUCCESS;
    unsigned char imsiBuffer[33];
    tee_rv = TEE_DigestDoFinal(sessionContext, params[1].memref.buffer, params[1].memref.size,
            imsiBuffer, 33);
    tee_rv = TEE_DigestDoFinal(sessionContext, imsiBuffer, 33, params[2].memref.buffer,
            params[2].memref.size);
    return tee_rv;
}

TEE_Result hashWithNetwork(void* sessionContext, TEE_Param params[4]){
    TEE_Result rv = TEE_ERROR_GENERIC;
    sessionContext = sessionContext;
    switch(params[0].value.a){
        case 0: // Bitcoin
            rv = doubleHash(sessionContext, params);
            break;
        case 1: // Ethereum, Not yet.
            break;
    }
    return rv;
}

TEE_Result TA_EXPORT TA_InvokeCommandEntryPoint(void *sessionContext,
						uint32_t commandID,
						uint32_t paramTypes,
						TEE_Param params[4])
{
	TEE_Result rv = TEE_ERROR_GENERIC;

	sessionContext = sessionContext;

	// if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT ||
	//     TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_MEMREF_INPUT ||
    //     TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_MEMREF_OUTPUT) {
	// 	OT_LOG(LOG_ERR, "Bad parameter at index 0 OR 1 OR 2");
	// 	return TEE_ERROR_BAD_PARAMETERS;
	// }

	switch (commandID) {
        case HASH_DOFINAL:
            hashWithNetwork(sessionContext, params);
            break;
        case SIGN_DOFINAL:
            rv = TEE_AsymmetricSignDigest(TEE_GetInstanceData(), NULL, 0,
                    params[0].memref.buffer, params[0].memref.size,
                    params[1].memref.buffer, &params[1].memref.size);
            if (rv != TEE_SUCCESS) {
                OT_LOG(LOG_ERR, "Sign failed");
            }
            break;
        default:
            rv = TEE_ERROR_BAD_PARAMETERS;
	}
	return rv;
}
