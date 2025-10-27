\subsubsection{执行结果的安全传输}

合约在 TEE 内执行并完成输出处理后，最终的结果需要被安全地返回至普通世界，并以一种标准化的格式呈现。为了确保结果传输过程的安全性，系统实现了以下加密机制：

1. TEE 内部加密流程
   - 在 `execute_with_data` 函数生成标准格式输出后，使用与解密 bytecode 相同的密钥进行 AES-256-GCM 加密
   - 加密输出的格式为 `[nonce][encrypted_output+tag]`，其中：
     * `nonce`: 12字节随机数
     * `encrypted_output`: AES-GCM加密后的输出内容
     * `tag`: 16字节认证标签
   - 加密后的数据存储在 `output_buffer` 中，准备分块传输

2. 分块传输机制
   - 使用 `get_output` 命令分两个阶段传输：
     * 首先获取加密输出的总大小
     * 然后分块传输加密数据，每块最大 8192 字节

3. 普通世界解密处理
   - Host 端在 `receive_output_from_ta` 函数中：
     * 首先完整接收所有加密数据块
     * 提取 nonce 和加密内容
     * 使用相同的密钥进行解密
     * 验证认证标签确保数据完整性
   - 解密成功后得到原始的标准格式输出：
```
Result: <status_code>
Gas used: <gas_used>
Output: <hex_output>
```

此安全机制确保了：
- 输出数据的机密性（通过 AES-256-GCM 加密）
- 数据完整性（通过 GCM 认证标签）
- 防重放攻击（通过随机 nonce）
- 密钥一致性（Host 与 TA 使用相同的派生密钥）