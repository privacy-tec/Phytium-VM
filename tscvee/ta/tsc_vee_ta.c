/*
 * Copyright (c) 2024, TSC-VEE Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
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

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <sodium.h>

#include <stdint.h>
#include "tsc_privkey.h"

#include <tsc_vee_ta.h>

// 包含EVM相关头文件
#include "vm.h"
#include "instructions_traits.h"
#include "hex_helpers.h"
#include "mocked_host.h"

// 全局数据存储
static char *bytecode_buffer = NULL;
static size_t bytecode_size = 0;
static char *input_buffer = NULL;
static size_t input_size = 0;
static uint32_t gas_limit = 0;
static char *output_buffer = NULL;
static size_t output_size = 0;

/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("TSC-VEE TA created");
	/* initialize libsodium in TA (if libsodium is linked into the TA) */
	if (sodium_init() < 0) {
		IMSG("libsodium init failed in TA");
		return TEE_ERROR_GENERIC;
	}
	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("TSC-VEE TA destroyed");

	// 清理内存
	if (bytecode_buffer) {
		TEE_Free(bytecode_buffer);
		bytecode_buffer = NULL;
	}
	if (input_buffer) {
		TEE_Free(input_buffer);
		input_buffer = NULL;
	}
	if (output_buffer) {
		TEE_Free(output_buffer);
		output_buffer = NULL;
	}
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
				    TEE_Param __maybe_unused params[4],
				    void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("TSC-VEE TA session opened");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;

	/*
	 * The DMSG() macro is non-standard, TEE Internal API doesn't
	 * specify any means to logging from a TA.
	 */
	IMSG("TSC-VEE: TrustZone-based Smart Contract Virtual Execution Environment\n");

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)&sess_ctx; /* Unused parameter */
	IMSG("TSC-VEE session closed\n");
}

static TEE_Result init_transfer(uint32_t param_types, TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_NONE);

	DMSG("init_transfer called");
	IMSG("=== TSC-VEE INIT TRANSFER START ===");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	// 清理之前的数据
	if (bytecode_buffer) {
		TEE_Free(bytecode_buffer);
		bytecode_buffer = NULL;
	}
	if (input_buffer) {
		TEE_Free(input_buffer);
		input_buffer = NULL;
	}
	if (output_buffer) {
		TEE_Free(output_buffer);
		output_buffer = NULL;
	}

	// 获取大小信息
	bytecode_size = params[0].value.a;
	input_size = params[1].value.a;
	gas_limit = params[2].value.a;

	// 分配内存
	bytecode_buffer = TEE_Malloc(bytecode_size, 0);
	input_buffer = TEE_Malloc(input_size, 0);

	if (!bytecode_buffer || !input_buffer) {
		IMSG("Failed to allocate memory for data transfer");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	IMSG("Initialized transfer: bytecode_size=%zu, input_size=%zu, gas=%u",
	     bytecode_size, input_size, gas_limit);

	return TEE_SUCCESS;
}

static TEE_Result transfer_data(uint32_t param_types, TEE_Param params[4])
{
	DMSG("transfer_data called");

	uint32_t data_type = 0;
	size_t offset = 0;
	size_t chunk_size = 0;
	char *chunk_data = NULL;

	if (param_types == TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					   TEE_PARAM_TYPE_VALUE_INPUT,
					   TEE_PARAM_TYPE_VALUE_INPUT,
					   TEE_PARAM_TYPE_NONE)) {
		// 初始化调用
		data_type = 0;
	} else if (param_types == TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						  TEE_PARAM_TYPE_VALUE_INPUT,
						  TEE_PARAM_TYPE_VALUE_INPUT,
						  TEE_PARAM_TYPE_NONE)) {
		// 数据传输调用
		data_type = params[2].value.a;
		offset = params[1].value.a;
		chunk_size = params[0].memref.size;
		chunk_data = (char *)params[0].memref.buffer;
	} else {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (data_type == 0) {
		// 初始化传输
		if (bytecode_buffer) {
			TEE_Free(bytecode_buffer);
			bytecode_buffer = NULL;
		}
		if (input_buffer) {
			TEE_Free(input_buffer);
			input_buffer = NULL;
		}
		if (output_buffer) {
			TEE_Free(output_buffer);
			output_buffer = NULL;
		}

		// 获取大小信息
		bytecode_size = params[0].value.a;
		input_size = params[1].value.a;
		gas_limit = params[2].value.a;

		// 分配内存
		bytecode_buffer = TEE_Malloc(bytecode_size, 0);
		input_buffer = TEE_Malloc(input_size, 0);

		if (!bytecode_buffer || !input_buffer) {
			IMSG("Failed to allocate memory for data transfer");
			return TEE_ERROR_OUT_OF_MEMORY;
		}

		IMSG("Initialized transfer: bytecode_size=%zu, input_size=%zu, gas=%u",
		     bytecode_size, input_size, gas_limit);
	} else if (data_type == 1) {
		// 传输bytecode（接收为加密数据）
		if (!bytecode_buffer) {
			return TEE_ERROR_BAD_STATE;
		}
		if (offset + chunk_size > bytecode_size) {
			return TEE_ERROR_BAD_PARAMETERS;
		}
		/* Copy encrypted chunk into the bytecode_buffer. Decryption will be
		 * performed once the full blob is received (in execute_with_data).
		 */
		memcpy(bytecode_buffer + offset, chunk_data, chunk_size);
		IMSG("Received encrypted bytecode chunk: offset=%zu, size=%zu", offset, chunk_size);
	} else if (data_type == 2) {
		// 传输input
		if (!input_buffer) {
			return TEE_ERROR_BAD_STATE;
		}
		if (offset + chunk_size > input_size) {
			return TEE_ERROR_BAD_PARAMETERS;
		}
		memcpy(input_buffer + offset, chunk_data, chunk_size);
		IMSG("Received input chunk: offset=%zu, size=%zu", offset, chunk_size);
	} else {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static TEE_Result execute_with_data(uint32_t param_types, TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("execute_with_data called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!bytecode_buffer || !input_buffer) {
		IMSG("ERROR: No data buffers available");
		return TEE_ERROR_BAD_STATE;
	}

	// 验证接收到的数据
	IMSG("Executing with received data:");
	IMSG("-Bytecode size: %zu", bytecode_size);
	IMSG("-Input size: %zu", input_size);
	IMSG("-Gas limit: %u", gas_limit);

	// 严格按照REE项目的执行逻辑
	// 1. 初始化指令表
	GasCostTable_init(gas_costs);
	TraitsTable_init(traits);

	// 2. 创建VM实例
	struct evmc_vm *vm = (struct evmc_vm *)TEE_Malloc(sizeof(struct evmc_vm), 0);
	if (!vm) {
		IMSG("ERROR: Failed to allocate VM");
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	vm_init(vm);

	// 3. 设置EVM版本
	enum evmc_revision rev = EVMC_LONDON;

	// 4. 如果接收到的是加密的 bytecode（格式：[nonce][ciphertext+tag]），先解密，然后转换十六进制字符串为字节数组 - 严格按照REE的逻辑
	if (bytecode_buffer && bytecode_size > 0) {
		/* Expect at least nonce + tag */
		size_t nonce_len = crypto_aead_aes256gcm_NPUBBYTES;
		size_t tag_len = crypto_aead_aes256gcm_ABYTES;
		if (bytecode_size >= nonce_len + tag_len) {
			unsigned char *enc = (unsigned char *)bytecode_buffer;
			unsigned char *nonce = enc; /* first nonce_len bytes */
			unsigned char *cipher = enc + nonce_len;
			size_t cipher_len = bytecode_size - nonce_len;

			/* derive 32-byte key from passphrase */
			unsigned char key32[32];
			const char *ta_priv = TSC_PRIVKEY;
			size_t ta_priv_len = strlen(ta_priv);
			crypto_generichash(key32, sizeof(key32), (const unsigned char*)ta_priv,
			                   (unsigned long long)ta_priv_len, NULL, 0);

			unsigned long long mlen = 0;
			size_t max_mlen = cipher_len; /* upper bound */
			unsigned char *plaintext = (unsigned char *)TEE_Malloc(max_mlen + 1, 0);
			if (!plaintext) {
				IMSG("ERROR: Failed to allocate plaintext buffer for decryption");
				return TEE_ERROR_OUT_OF_MEMORY;
			}

			if (crypto_aead_aes256gcm_decrypt(plaintext, &mlen, NULL,
							cipher, (unsigned long long)cipher_len,
							NULL, 0,
							nonce, key32) != 0) {
				IMSG("Decryption of bytecode failed");
				TEE_Free(plaintext);
				return TEE_ERROR_SECURITY;
			}

			/* Null-terminate and replace bytecode_buffer */
			plaintext[mlen] = '\0';
			TEE_Free(bytecode_buffer);
			bytecode_buffer = (char *)plaintext;
			bytecode_size = (size_t)mlen;
			IMSG("Decrypted bytecode, plaintext size=%zu", bytecode_size);
		}
	}

	size_t code_size = bytecode_size / 2 - 1;  // 去掉0x前缀
	byte *code = (byte *)TEE_Malloc(sizeof(byte) * code_size, 0);
	if (!code) {
		TEE_Free(vm);
		IMSG("ERROR: Failed to allocate code buffer");
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	from_hex(bytecode_buffer, code);

	size_t input_hex_size = input_size / 2 - 1;  // 去掉0x前缀
	byte *input = (byte *)TEE_Malloc(sizeof(byte) * input_hex_size, 0);
	if (!input) {
		TEE_Free(code);
		TEE_Free(vm);
		IMSG("ERROR: Failed to allocate input buffer");
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	from_hex(input_buffer, input);

	// 5. 创建模拟主机接口
	MockedHost* host = (MockedHost*)TEE_Malloc(sizeof(MockedHost), 0);
	if (!host) {
		TEE_Free(input);
		TEE_Free(code);
		TEE_Free(vm);
		IMSG("ERROR: Failed to allocate host");
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	MockedHost_init(host);

	// 6. 创建消息
	struct evmc_message* msg = (struct evmc_message*)TEE_Malloc(sizeof(struct evmc_message), 0);
	if (!msg) {
		TEE_Free(host);
		TEE_Free(input);
		TEE_Free(code);
		TEE_Free(vm);
		IMSG("ERROR: Failed to allocate message");
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	EVMCMessage_init_v(msg, gas_limit, input, input_hex_size);

	// 7. 执行EVM代码
	DMSG("Executing EVM code...");
	struct evmc_result result = vm->execute(vm, host, rev, msg, code, code_size);

	// 8. 处理执行结果 - 严格按照REE的输出格式
	int64_t gas_used = msg->gas - result.gas_left;
	DMSG("Execution completed:");
	DMSG("-Status code: %d", result.status_code);
	DMSG("-Gas used: %ld", gas_used);
	DMSG("-Output size: %zu", result.output_size);

	// 9. 生成输出报告 - 严格与REE保持一致
	if (output_buffer) {
		TEE_Free(output_buffer);
	}

	// 分配足够大的输出缓冲区
	output_size = 8192;
	output_buffer = TEE_Malloc(output_size, 0);
	if (!output_buffer) {
		// 清理资源
		if (result.release) result.release(&result);
		TEE_Free(msg);
		TEE_Free(host);
		TEE_Free(input);
		TEE_Free(code);
		TEE_Free(vm);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	// 严格按照REE的输出格式构建字符串
	size_t pos = 0;

	// "\nResult: <status_code>\n"
	strcpy(output_buffer, "\nResult: ");
	pos = strlen(output_buffer);

	// 转换status_code到字符串
	char status_str[16];
	int status = result.status_code;
	int status_pos = 0;
	if (status == 0) {
		strcpy(status_str, "0");
	} else {
		while (status > 0) {
			status_str[status_pos++] = '0' + (status % 10);
			status /= 10;
		}
		status_str[status_pos] = '\0';
		// 反转字符串
		for (int i = 0; i < status_pos/2; i++) {
			char temp = status_str[i];
			status_str[i] = status_str[status_pos-1-i];
			status_str[status_pos-1-i] = temp;
		}
	}
	strcpy(output_buffer + pos, status_str);
	pos = strlen(output_buffer);
	strcpy(output_buffer + pos, "\n");
	pos = strlen(output_buffer);

	// "Gas used: <gas_used>\n"
	strcpy(output_buffer + pos, "Gas used: ");
	pos = strlen(output_buffer);

	// 转换gas_used到字符串
	char gas_str[32];
	int gas_pos = 0;
	long gas = gas_used;
	if (gas == 0) {
		strcpy(gas_str, "0");
	} else {
		while (gas > 0) {
			gas_str[gas_pos++] = '0' + (gas % 10);
			gas /= 10;
		}
		gas_str[gas_pos] = '\0';
		// 反转字符串
		for (int i = 0; i < gas_pos/2; i++) {
			char temp = gas_str[i];
			gas_str[i] = gas_str[gas_pos-1-i];
			gas_str[gas_pos-1-i] = temp;
		}
	}
	strcpy(output_buffer + pos, gas_str);
	pos = strlen(output_buffer);
	strcpy(output_buffer + pos, "\n");
	pos = strlen(output_buffer);

	// "Output: <hex_output>\n" (如果成功或revert) - 严格按照REE的格式
	if (result.status_code == EVMC_SUCCESS || result.status_code == EVMC_REVERT) {
		if (result.output_size > 0) {
			// 按照REE的格式：outlen = result.output_size * 2 + 2
			size_t outlen = result.output_size * 2 + 2;
			char *output_hex = (char *)TEE_Malloc(sizeof(char) * outlen, 0);
			if (output_hex) {
				hex(result.output_data, result.output_size, output_hex);

				strcpy(output_buffer + pos, "Output: ");
				pos = strlen(output_buffer);

				// 按照REE的格式，逐个字符输出
				for (int i = 0; i < outlen; i++) {
					output_buffer[pos++] = output_hex[i];
				}
				output_buffer[pos] = '\0';
				pos = strlen(output_buffer);
				strcpy(output_buffer + pos, "\n");

				TEE_Free(output_hex);
			}
		}
	}

	size_t plaintext_len = strlen(output_buffer);
	IMSG("Generated plaintext output of size: %zu", plaintext_len);

	/* Encrypt the output before sending back to host */
	unsigned char key32[32];
	const char *ta_priv = TSC_PRIVKEY;
	size_t ta_priv_len = strlen(ta_priv);
	crypto_generichash(key32, sizeof(key32),
			   (const unsigned char*)ta_priv,
			   (unsigned long long)ta_priv_len,
			   NULL, 0);

	/* Format: [nonce][encrypted_output+tag] */
	const size_t nonce_len = crypto_aead_aes256gcm_NPUBBYTES;
	unsigned char nonce[crypto_aead_aes256gcm_NPUBBYTES];
	randombytes_buf(nonce, nonce_len);

	size_t ciphertext_len = plaintext_len + crypto_aead_aes256gcm_ABYTES;
	unsigned char *ciphertext = TEE_Malloc(ciphertext_len, 0);
	if (!ciphertext) {
		IMSG("Failed to allocate ciphertext buffer");
		if (result.release) result.release(&result);
		TEE_Free(msg);
		TEE_Free(host);
		TEE_Free(input);
		TEE_Free(code);
		TEE_Free(vm);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	unsigned long long clen;
	if (crypto_aead_aes256gcm_encrypt(ciphertext, &clen,
					 (const unsigned char*)output_buffer,
					 (unsigned long long)plaintext_len,
					 NULL, 0,
					 NULL,
					 nonce, key32) != 0) {
		IMSG("Output encryption failed");
		TEE_Free(ciphertext);
		if (result.release) result.release(&result);
		TEE_Free(msg);
		TEE_Free(host);
		TEE_Free(input);
		TEE_Free(code);
		TEE_Free(vm);
		return TEE_ERROR_GENERIC;
	}

	/* Replace output_buffer with [nonce][ciphertext] */
	TEE_Free(output_buffer);
	output_size = nonce_len + ciphertext_len;
	output_buffer = TEE_Malloc(output_size, 0);
	if (!output_buffer) {
		IMSG("Failed to allocate encrypted output buffer");
		TEE_Free(ciphertext);
		if (result.release) result.release(&result);
		TEE_Free(msg);
		TEE_Free(host);
		TEE_Free(input);
		TEE_Free(code);
		TEE_Free(vm);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	memcpy(output_buffer, nonce, nonce_len);
	memcpy(output_buffer + nonce_len, ciphertext, ciphertext_len);
	TEE_Free(ciphertext);

	IMSG("Output encrypted: original_size=%zu, encrypted_size=%zu",
	     plaintext_len, output_size);

	// 清理资源
	if (result.release) result.release(&result);
	TEE_Free(msg);
	TEE_Free(host);
	TEE_Free(input);
	TEE_Free(code);
	TEE_Free(vm);

	return TEE_SUCCESS;
}

static TEE_Result get_output(uint32_t param_types, TEE_Param params[4])
{
	DMSG("get_output called");

	if (!output_buffer) {
		return TEE_ERROR_BAD_STATE;
	}

	uint32_t request_type = 0;
	size_t offset = 0;
	size_t chunk_size = 0;
	char *chunk_buffer = NULL;

	// 检查参数类型 - 支持两种调用方式
	if (param_types == TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
					   TEE_PARAM_TYPE_MEMREF_OUTPUT,
					   TEE_PARAM_TYPE_VALUE_INPUT,
					   TEE_PARAM_TYPE_NONE)) {
		// 获取输出大小
		request_type = params[2].value.a;
	} else if (param_types == TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
						  TEE_PARAM_TYPE_MEMREF_OUTPUT,
						  TEE_PARAM_TYPE_VALUE_INPUT,
						  TEE_PARAM_TYPE_VALUE_INPUT)) {
		// 获取输出块
		request_type = params[2].value.a;
		offset = params[3].value.a;
		chunk_size = params[1].memref.size;
		chunk_buffer = (char *)params[1].memref.buffer;
	} else {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (request_type == 0) {
		// 获取输出大小
		params[0].value.a = output_size;
		IMSG("Output size: %zu", output_size);
	} else if (request_type == 1) {
		// 获取输出块
		if (offset >= output_size) {
			return TEE_ERROR_BAD_PARAMETERS;
		}

		size_t actual_chunk_size = (offset + chunk_size > output_size) ?
					   (output_size - offset) : chunk_size;

		memcpy(chunk_buffer, output_buffer + offset, actual_chunk_size);
		params[1].memref.size = actual_chunk_size;
		// 保持params[0].value.a不变，让host端知道总大小

		IMSG("Sent output chunk: offset=%zu, size=%zu", offset, actual_chunk_size);
	} else {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static TEE_Result get_version(uint32_t param_types, TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("get_version called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	const char *version = "TSC-VEE v0.1.0";
	size_t len = strlen(version) + 1;

	if (params[0].memref.size < len)
		return TEE_ERROR_SHORT_BUFFER;

	memcpy(params[0].memref.buffer, version, len);
	params[0].memref.size = len;

	return TEE_SUCCESS;
}

/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
				      uint32_t cmd_id,
				      uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */

	switch (cmd_id) {
	case TA_TSC_VEE_CMD_GET_VERSION:
		return get_version(param_types, params);
	case TA_TSC_VEE_CMD_TRANSFER_DATA:
		return transfer_data(param_types, params);
	case TA_TSC_VEE_CMD_EXECUTE_WITH_DATA:
		return execute_with_data(param_types, params);
	case TA_TSC_VEE_CMD_GET_OUTPUT:
		return get_output(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
} 