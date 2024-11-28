/*
 * Copyright (c) 2024, TSC-VEE Project
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
#include <tsc_vee_ta.h>

/* cJSON for parsing JSON files */
#include "cJSON.h"

/* Maximum chunk size for data transfer */
#define MAX_CHUNK_SIZE 8192

// 分段传输数据到 TA
static TEEC_Result transfer_data_to_ta(TEEC_Session *sess, 
                                      const char *data, 
                                      size_t data_size,
                                      uint32_t cmd_id,
                                      uint32_t data_type)
{
        TEEC_Result res;
        TEEC_Operation op;
        uint32_t err_origin;
        size_t offset = 0;
        char chunk_buffer[MAX_CHUNK_SIZE];

        while (offset < data_size) {
                size_t chunk_size = (data_size - offset > MAX_CHUNK_SIZE) ? 
                                   MAX_CHUNK_SIZE : (data_size - offset);
                
                memcpy(chunk_buffer, data + offset, chunk_size);

                memset(&op, 0, sizeof(op));
                op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                                 TEEC_VALUE_INPUT,
                                                 TEEC_VALUE_INPUT,
                                                 TEEC_NONE);
                op.params[0].tmpref.buffer = chunk_buffer;
                op.params[0].tmpref.size = chunk_size;
                op.params[1].value.a = offset;
                op.params[2].value.a = data_type;

                res = TEEC_InvokeCommand(sess, cmd_id, &op, &err_origin);
                if (res != TEEC_SUCCESS) {
                        printf("Failed to transfer chunk at offset %zu: 0x%x\n", 
                               offset, res);
                        return res;
                }

                offset += chunk_size;
                printf("Transferred chunk: offset=%zu, size=%zu\n", 
                       offset - chunk_size, chunk_size);
        }

        return TEEC_SUCCESS;
}

// 从 TA 分段接收输出数据
static TEEC_Result receive_output_from_ta(TEEC_Session *sess, char **output_data)
{
        TEEC_Result res;
        TEEC_Operation op;
        uint32_t err_origin;
        size_t total_size = 0;
        size_t offset = 0;
        char chunk_buffer[MAX_CHUNK_SIZE];

        // 首先获取输出大小
        memset(&op, 0, sizeof(op));
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT,
                                         TEEC_MEMREF_TEMP_OUTPUT,
                                         TEEC_VALUE_INPUT,
                                         TEEC_NONE);
        op.params[2].value.a = 0; // 请求类型：获取大小

        res = TEEC_InvokeCommand(sess, TA_TSC_VEE_CMD_GET_OUTPUT, &op, &err_origin);
        if (res != TEEC_SUCCESS) {
                printf("Failed to get output size: 0x%x\n", res);
                return res;
        }

        total_size = op.params[0].value.a;
        printf("Output size: %zu\n", total_size);

        if (total_size == 0) {
                *output_data = NULL;
                return TEEC_SUCCESS;
        }

        // 分配输出缓冲区
        *output_data = malloc(total_size);
        if (!*output_data) {
                printf("Failed to allocate output buffer\n");
                return TEEC_ERROR_OUT_OF_MEMORY;
        }

        // 分段接收输出数据
        while (offset < total_size) {
                size_t chunk_size = (total_size - offset > MAX_CHUNK_SIZE) ? 
                                   MAX_CHUNK_SIZE : (total_size - offset);

                memset(&op, 0, sizeof(op));
                op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT,
                                                 TEEC_MEMREF_TEMP_OUTPUT,
                                                 TEEC_VALUE_INPUT,
                                                 TEEC_VALUE_INPUT);
                op.params[0].value.a = total_size; // 输出大小
                op.params[1].tmpref.buffer = chunk_buffer;
                op.params[1].tmpref.size = chunk_size;
                op.params[2].value.a = 1; // 请求类型：获取块
                op.params[3].value.a = offset; // 偏移量

                res = TEEC_InvokeCommand(sess, TA_TSC_VEE_CMD_GET_OUTPUT, &op, &err_origin);
                if (res != TEEC_SUCCESS) {
                        printf("Failed to get output chunk at offset %zu: 0x%x\n", offset, res);
                        free(*output_data);
                        *output_data = NULL;
                        return res;
                }

                size_t actual_chunk_size = op.params[1].tmpref.size;
                memcpy(*output_data + offset, chunk_buffer, actual_chunk_size);
                offset += actual_chunk_size;

                printf("Received output chunk: offset=%zu, size=%zu\n", 
                       offset - actual_chunk_size, actual_chunk_size);

                if (actual_chunk_size < chunk_size) {
                        break; // 已经接收完所有数据
                }
        }
        return TEEC_SUCCESS;
}

int main(int argc, char *argv[])
{
        TEEC_Result res;
        TEEC_Context ctx;
        TEEC_Session sess;
        TEEC_Operation op;
        TEEC_UUID uuid = TA_TSC_VEE_UUID;
        uint32_t err_origin;

        // 检查命令行参数
        if (argc != 2) {
                printf("Usage: %s <json_file_path>\n", argv[0]);
                printf("Example: %s args/transferFrom.json\n", argv[0]);
                return -1;
        }

        const char *json_file_path = argv[1];

        // Read file and get input data - 严格按照原始 ree 项目的格式
        FILE *fp = NULL;
        fp = fopen(json_file_path, "r");
        if (fp == NULL) {
                printf("Failed to open %s\n", json_file_path);
                return -1;
        }
        
        fseek(fp, 0L, SEEK_END);
        long flen = ftell(fp);
        char *p = (char *)malloc(flen + 1);
        if (p == NULL)
        {
                fclose(fp);
                printf("Input data is Empty!\n");
                return -1;
        }
        fseek(fp, 0L, SEEK_SET);
        fread(p, flen, 1, fp);
        p[flen] = 0;
        fclose(fp);

        // Parse json data - 严格按照原始 ree 项目的格式
        cJSON *cjson_content = NULL;
        cJSON *cjson_bytecode = NULL;
        cJSON *cjson_input = NULL;
        cJSON *cjson_gas = NULL;
        cjson_content = cJSON_Parse(p);
        if (cjson_content == NULL)
        {
                printf("Parse fail.\n");
                free(p);
                return -1;
        }
        cjson_bytecode = cJSON_GetObjectItem(cjson_content, "bytecode");
        cjson_input = cJSON_GetObjectItem(cjson_content, "input");
        cjson_gas = cJSON_GetObjectItem(cjson_content, "gas");
        
        printf("Bytecode: %s\n", cjson_bytecode->valuestring);
        printf("Input: %s\n", cjson_input->valuestring);
        printf("Gas: %d\n", cjson_gas->valueint);

        /* Initialize a context connecting us to the TEE */
        res = TEEC_InitializeContext(NULL, &ctx);
        if (res != TEEC_SUCCESS)
                errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

        /*
         * Open a session to the TSC-VEE TA
         */
        res = TEEC_OpenSession(&ctx, &sess, &uuid,
                               TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
        if (res != TEEC_SUCCESS)
                errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
                        res, err_origin);

        /*
         * Initialize transfer with size information
         */
        memset(&op, 0, sizeof(op));
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
                                         TEEC_VALUE_INPUT,
                                         TEEC_VALUE_INPUT,
                                         TEEC_NONE);
        op.params[0].value.a = strlen(cjson_bytecode->valuestring);
        op.params[1].value.a = strlen(cjson_input->valuestring);
        op.params[2].value.a = cjson_gas->valueint;

        printf("\n=== TSC-VEE DATA TRANSFER ===\n");
        printf("Initializing transfer with sizes: bytecode=%d, input=%d, gas=%d\n",
               op.params[0].value.a, op.params[1].value.a, op.params[2].value.a);

        res = TEEC_InvokeCommand(&sess, TA_TSC_VEE_CMD_TRANSFER_DATA, &op,
                                 &err_origin);
        if (res != TEEC_SUCCESS)
                errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
                        res, err_origin);

        /*
         * Transfer bytecode in chunks
         */
        printf("Transferring bytecode (%zu bytes)...\n", strlen(cjson_bytecode->valuestring));
        res = transfer_data_to_ta(&sess, cjson_bytecode->valuestring, 
                                 strlen(cjson_bytecode->valuestring),
                                 TA_TSC_VEE_CMD_TRANSFER_DATA, 1);
        if (res != TEEC_SUCCESS)
                errx(1, "Failed to transfer bytecode: 0x%x", res);

        /*
         * Transfer input in chunks
         */
        printf("Transferring input (%zu bytes)...\n", strlen(cjson_input->valuestring));
        res = transfer_data_to_ta(&sess, cjson_input->valuestring,
                                 strlen(cjson_input->valuestring),
                                 TA_TSC_VEE_CMD_TRANSFER_DATA, 2);
        if (res != TEEC_SUCCESS)
                errx(1, "Failed to transfer input: 0x%x", res);

        /*
         * Execute with transferred data
         */
        printf("Executing TEE computation...\n");
        memset(&op, 0, sizeof(op));
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE,
                                         TEEC_NONE,
                                         TEEC_NONE,
                                         TEEC_NONE);

        res = TEEC_InvokeCommand(&sess, TA_TSC_VEE_CMD_EXECUTE_WITH_DATA, &op,
                                 &err_origin);
        if (res != TEEC_SUCCESS)
                errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
                        res, err_origin);

        /*
         * Receive output data in chunks
         */
        printf("Receiving TEE results...\n");
        char *output_data = NULL;
        res = receive_output_from_ta(&sess, &output_data);
        if (res != TEEC_SUCCESS)
                errx(1, "Failed to receive output: 0x%x", res);

        if (output_data) {
                printf("\n=== TEE EXECUTION RESULTS ===\n");
                printf("TA output: \n%s\n", output_data);
                printf("=== END TEE RESULTS ===\n");
                free(output_data);
        } else {
                printf("No output data received\n");
        }

        /*
         * We're done with the TA, close the session and
         * destroy the context.
         */
        TEEC_CloseSession(&sess);
        TEEC_FinalizeContext(&ctx);

        // Cleanup
        cJSON_Delete(cjson_content);
        free(p);

        return 0;
}
