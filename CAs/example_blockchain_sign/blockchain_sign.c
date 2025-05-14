#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tee_client_api.h"
#include "blockchain_sign_ctrl.h"

int main(){
	TEEC_Context context;
	TEEC_Session session;
	TEEC_Operation operation = {0};
	TEEC_SharedMemory in_mem = {0};
	TEEC_SharedMemory out_mem = {0};
	TEEC_Result tee_rv;

    unsigned char sig[72];

	memset((void *)&in_mem, 0, sizeof(in_mem));
	memset((void *)&out_mem, 0, sizeof(out_mem));
	memset((void *)&operation, 0, sizeof(operation));
    
	tee_rv = TEEC_InitializeContext(NULL, &context);
    	if (tee_rv != TEEC_SUCCESS) {
		printf("TEEC_InitializeContext failed: 0x%x\n", tee_rv);
		goto end_1;
	}

    tee_rv = TEEC_OpenSession(&context, &session,
				  &uuid, TEEC_LOGIN_PUBLIC,
				  NULL, NULL, NULL);
	if (tee_rv != TEEC_SUCCESS) {
		printf("TEEC_OpenSession failed: 0x%x\n", tee_rv);
		goto end_2;
	}

    strcpy(in_mem.buffer, "\x18Bitcoin Signed Message:\n\x05hello");
    in_mem.size = strlen("\x18Bitcoin Signed Message:\n\x05hello");
    in_mem.flags = TEEC_MEM_INPUT;

    tee_rv = TEEC_RegisterSharedMemory(&context, &in_mem);
	if (tee_rv != TEE_SUCCESS) {
		printf("Failed to allocate OUT shared memory\n");
		goto end_3;
	}    

    out_mem.buffer = sig;
	out_mem.size = 72;
	out_mem.flags = TEEC_MEM_OUTPUT;

	tee_rv = TEEC_RegisterSharedMemory(&context, &out_mem);
	if (tee_rv != TEE_SUCCESS) {
		printf("Failed to allocate OUT shared memory\n");
		goto end_3;
	}

    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,TEEC_MEMREF_WHOLE, 
						TEEC_MEMREF_WHOLE, TEEC_NONE);
	operation.params[0].value.a = 0;
    operation.params[1].memref.parent = &in_mem;
	operation.params[2].memref.parent = &out_mem;
	tee_rv = TEEC_InvokeCommand(&session, SIGN_UPDATE, &operation, NULL);
	if (tee_rv != TEEC_SUCCESS) {
		printf("TEEC_InvokeCommand failed: 0x%x\n", tee_rv);
		goto end_4;
	}

    tee_rv = TEEC_InvokeCommand(&session, SIGN_DOFINAL, NULL, NULL);
    	if (tee_rv != TEEC_SUCCESS) {
		printf("TEEC_InvokeCommand failed: 0x%x\n", tee_rv);
		goto end_4;
	}

    puts(sig);

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