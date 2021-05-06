/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

#define MAX_LEN 200
#define RSA_KEY_SIZE 1024
#define MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)


int main(int argc, char* argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	char plaintext[MAX_LEN] = {0, };
	char ciphertext[MAX_LEN] = {0, };
	char key[10] = {0, };

	char* command = argv[1];
	char* fname = argv[2];
	char* cipher = argv[3];

	FILE* fp;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);


	/* Clear the TEEC_Operation struct */
	memset(&op, 0, sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_MEMREF_TEMP_INOUT,
					 TEEC_NONE, TEEC_NONE);
	
	

	if(!strcmp(command, "-e")){
		// encrypt

		fp = fopen(fname, "r"); // file open
		if(fp == NULL){
			perror("file open error");
			exit(-1);
		}

		fread(plaintext, 1, MAX_LEN, fp);
		fclose(fp);

		op.params[0].tmpref.buffer = plaintext;
		op.params[0].tmpref.size = MAX_LEN;

		if(!strcmp(cipher, "Caesar")){
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_ENC, &op,
				 	&err_origin);
			
			if(res != TEEC_SUCCESS)
				errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
			memcpy(ciphertext, op.params[0].tmpref.buffer, MAX_LEN);
			fp = fopen("encrypt.txt", "w");
			fputs(ciphertext, fp);
			fclose(fp);

			op.params[0].tmpref.buffer = key;
			op.params[0].tmpref.size = sizeof(key);

			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_GET_KEY, &op,
				 	&err_origin);
			if(res != TEEC_SUCCESS)
				errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
					res, err_origin);
			fp = fopen("cipher.txt", "w");
			fputs(key, fp);
			fclose(fp);
		}
		else if(!strcmp(cipher, "RSA")){
			op.params[0].tmpref.size = MAX_PLAIN_LEN_1024;
			op.params[1].tmpref.buffer = ciphertext;
			op.params[1].tmpref.size = RSA_CIPHER_LEN_1024;

			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_RSA_GENKEYS, &op,
					&err_origin);
			if (res != TEEC_SUCCESS)
				errx(1, "\nTEEC_InvokeCommand(RSA_GENKEYS) failed %#x\n", res);
			printf("\n=========== Keys already generated. ==========\n");
			
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_RSA_ENC, &op,
				 	&err_origin);
			
			if(res != TEEC_SUCCESS)
				errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
			fp = fopen("encrypt.txt", "w");
			fputs(ciphertext, fp);
			fclose(fp);
		}
		else{
			printf("cipher error\n");
			exit(-1);
		}
	}
	else if(!strcmp(command, "-d")){
		// decrypt
		
		char* fkey = argv[3]; 
		fp = fopen(fkey, "r"); // file open
		
		if(fp == NULL){
			perror("file open error");
			exit(-1);
		}

		fread(key, 1, sizeof(key), fp);
		fclose(fp);
		
		op.params[0].tmpref.buffer = key;
		op.params[0].tmpref.size = sizeof(key);

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_SEND_KEY, &op,
				 	&err_origin);
		if(res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", 
				res, err_origin);

		fp = fopen(fname, "r"); // file open
		if(fp == NULL){
			perror("file open error");
			exit(-1);
		}

		fread(ciphertext, 1, MAX_LEN, fp);
		fclose(fp);

		op.params[0].tmpref.buffer = ciphertext;
		op.params[0].tmpref.size = MAX_LEN;

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_DEC, &op,
				 	&err_origin);
		if(res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", 
				res, err_origin);

		memcpy(plaintext, op.params[0].tmpref.buffer, MAX_LEN);

		fp = fopen("decrypt.txt", "w");
		fputs(plaintext, fp);
		fclose(fp);
	}
	
	printf("\n=========== EXIT ===========\n");
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return 0;
}
