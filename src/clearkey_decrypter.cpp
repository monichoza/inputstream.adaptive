/*
 *      Copyright (C) 2024 inputstream.adaptive
 *
 *  This Program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This Program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  <http://www.gnu.org/licenses/>.
 *
 */

#include "clearkey_decrypter.h"
#include "helpers.h"
#include "log.h"
#include "../lib/libbento4/Crypto/Ap4StreamCipher.h"
#include "../lib/libbento4/Core/Ap4.h"
#include <algorithm>
#include <sstream>
#include <cstring>
#include <cstdarg>

extern SSD::SSD_HOST *host;

static void Log(SSD::SSD_HOST::LOGLEVEL loglevel, const char *format, ...)
{
  if (!host) return;
  
  char buffer[16384];
  va_list args;
  va_start(args, format);
  vsprintf(buffer, format, args);
  va_end(args);
  return host->Log(loglevel, buffer);
}

// ClearKey system ID as defined in EME specification
static const uint8_t CLEARKEY_SYSTEM_ID[16] = {
    0xe2, 0x71, 0x9d, 0x58, 0xa9, 0x85, 0xb3, 0xc9,
    0x78, 0x1a, 0xb0, 0x30, 0xaf, 0x78, 0xd3, 0x0e
};

ClearKeyDecrypter::ClearKeyDecrypter()
    : m_initialized(false)
{
}

ClearKeyDecrypter::~ClearKeyDecrypter()
{
}

const char* ClearKeyDecrypter::SelectKeySytem(const char* keySystem)
{
    if (!keySystem)
        return nullptr;

    // Support both the standard ClearKey system ID and common variations
    if (strcmp(keySystem, "org.w3.clearkey") == 0 ||
        strcmp(keySystem, "webkit-org.w3.clearkey") == 0 ||
        strcmp(keySystem, "clearkey") == 0)
    {
        return "org.w3.clearkey";
    }

    return nullptr;
}

bool ClearKeyDecrypter::OpenDRMSystem(const char* licenseURL, const AP4_DataBuffer& serverCertificate, const uint8_t config)
{
    if (licenseURL)
        m_licenseUrl = licenseURL;

    m_initialized = true;
    Log(SSD::SSD_HOST::LL_DEBUG, "ClearKey DRM system opened successfully");
    return true;
}

AP4_CencSingleSampleDecrypter* ClearKeyDecrypter::CreateSingleSampleDecrypter(AP4_DataBuffer& pssh, const char* optionalKeyParameter, const uint8_t* defaultkeyid)
{
    // Parse keys from optionalKeyParameter if provided
    if (optionalKeyParameter && strlen(optionalKeyParameter) > 0)
    {
        if (!ParseClearKeyLicense(optionalKeyParameter))
        {
            Log(SSD::SSD_HOST::LL_ERROR, "Failed to parse ClearKey license data");
            return nullptr;
        }
    }

    // Find the appropriate key
    const KeyInfo* keyInfo = nullptr;
    if (defaultkeyid)
    {
        keyInfo = FindKey(defaultkeyid);
    }
    else if (!m_keys.empty())
    {
        // Use the first available key if no specific key ID is provided
        keyInfo = &m_keys[0];
    }

    if (!keyInfo)
    {
        Log(SSD::SSD_HOST::LL_ERROR, "No suitable key found for ClearKey decryption");
        return nullptr;
    }

    // Create the single sample decrypter
    ClearKeySingleSampleDecrypter* decrypter = new ClearKeySingleSampleDecrypter(
        keyInfo->key.data(), keyInfo->key.size());

    Log(SSD::SSD_HOST::LL_DEBUG, "ClearKey single sample decrypter created");
    return decrypter;
}

void ClearKeyDecrypter::DestroySingleSampleDecrypter(AP4_CencSingleSampleDecrypter* decrypter)
{
    delete decrypter;
}

void ClearKeyDecrypter::GetCapabilities(AP4_CencSingleSampleDecrypter* decrypter, const uint8_t* keyid, uint32_t media, SSD_DECRYPTER::SSD_CAPS& caps)
{
    caps.flags = 0; // No special capabilities needed for ClearKey
    caps.hdcpVersion = 0; // No HDCP restrictions
    caps.hdcpLimit = 0;
}

bool ClearKeyDecrypter::HasLicenseKey(AP4_CencSingleSampleDecrypter* decrypter, const uint8_t* keyid)
{
    return FindKey(keyid) != nullptr;
}

bool ClearKeyDecrypter::OpenVideoDecoder(AP4_CencSingleSampleDecrypter* decrypter, const SSD::SSD_VIDEOINITDATA* initData)
{
    // ClearKey doesn't need a video decoder - decryption only
    return false;
}

SSD::SSD_DECODE_RETVAL ClearKeyDecrypter::DecodeVideo(void* instance, SSD::SSD_SAMPLE* sample, SSD::SSD_PICTURE* picture)
{
    // ClearKey doesn't provide video decoding
    return SSD::VC_ERROR;
}

void ClearKeyDecrypter::ResetVideo()
{
    // Nothing to reset for ClearKey
}

bool ClearKeyDecrypter::ParseClearKeyLicense(const std::string& licenseData)
{
    // Try to parse as JSON first
    if (licenseData.find('{') != std::string::npos)
    {
        return ParseJSONKeys(licenseData);
    }

    // Try to parse as simple key:value format
    // Format: keyid1:key1,keyid2:key2,...
    std::istringstream ss(licenseData);
    std::string keyPair;
    
    m_keys.clear();
    
    while (std::getline(ss, keyPair, ','))
    {
        size_t colonPos = keyPair.find(':');
        if (colonPos == std::string::npos)
            continue;

        std::string keyIdStr = keyPair.substr(0, colonPos);
        std::string keyStr = keyPair.substr(colonPos + 1);

        // Remove whitespace
        keyIdStr.erase(std::remove_if(keyIdStr.begin(), keyIdStr.end(), ::isspace), keyIdStr.end());
        keyStr.erase(std::remove_if(keyStr.begin(), keyStr.end(), ::isspace), keyStr.end());

        // Convert hex strings to binary
        std::vector<uint8_t> keyId = hexStringToBytes(keyIdStr);
        std::vector<uint8_t> key = hexStringToBytes(keyStr);

        if (keyId.size() == 16 && key.size() == 16)
        {
            KeyInfo info;
            info.keyId = keyId;
            info.key = key;
            m_keys.push_back(info);
        }
    }

    return !m_keys.empty();
}

bool ClearKeyDecrypter::ParseJSONKeys(const std::string& jsonData)
{
    // Simple JSON parsing for ClearKey format
    // Expected format: {"keys":[{"kty":"oct","k":"base64key","kid":"base64keyid"},...]}
    
    m_keys.clear();
    
    size_t keysPos = jsonData.find("\"keys\"");
    if (keysPos == std::string::npos)
        return false;

    size_t arrayStart = jsonData.find('[', keysPos);
    size_t arrayEnd = jsonData.find(']', arrayStart);
    if (arrayStart == std::string::npos || arrayEnd == std::string::npos)
        return false;

    std::string keysArray = jsonData.substr(arrayStart + 1, arrayEnd - arrayStart - 1);
    
    // Parse each key object
    size_t pos = 0;
    while (pos < keysArray.length())
    {
        size_t objStart = keysArray.find('{', pos);
        if (objStart == std::string::npos)
            break;

        size_t objEnd = keysArray.find('}', objStart);
        if (objEnd == std::string::npos)
            break;

        std::string keyObj = keysArray.substr(objStart, objEnd - objStart + 1);
        
        // Extract kid and k values
        std::string kidValue, kValue;
        
        size_t kidPos = keyObj.find("\"kid\"");
        if (kidPos != std::string::npos)
        {
            size_t kidStart = keyObj.find('\"', kidPos + 5);
            size_t kidEnd = keyObj.find('\"', kidStart + 1);
            if (kidStart != std::string::npos && kidEnd != std::string::npos)
                kidValue = keyObj.substr(kidStart + 1, kidEnd - kidStart - 1);
        }

        size_t kPos = keyObj.find("\"k\"");
        if (kPos != std::string::npos)
        {
            size_t kStart = keyObj.find('\"', kPos + 3);
            size_t kEnd = keyObj.find('\"', kStart + 1);
            if (kStart != std::string::npos && kEnd != std::string::npos)
                kValue = keyObj.substr(kStart + 1, kEnd - kStart - 1);
        }

        if (!kidValue.empty() && !kValue.empty())
        {
            // Decode base64url values
            std::vector<uint8_t> keyId = base64urlDecode(kidValue);
            std::vector<uint8_t> key = base64urlDecode(kValue);

            if (keyId.size() == 16 && key.size() == 16)
            {
                KeyInfo info;
                info.keyId = keyId;
                info.key = key;
                m_keys.push_back(info);
            }
        }

        pos = objEnd + 1;
    }

    return !m_keys.empty();
}

const ClearKeyDecrypter::KeyInfo* ClearKeyDecrypter::FindKey(const uint8_t* keyId) const
{
    if (!keyId)
        return nullptr;

    for (const auto& keyInfo : m_keys)
    {
        if (memcmp(keyInfo.keyId.data(), keyId, 16) == 0)
            return &keyInfo;
    }

    return nullptr;
}

// ClearKeySingleSampleDecrypter implementation

ClearKeySingleSampleDecrypter::ClearKeySingleSampleDecrypter(const uint8_t* key, AP4_Size keySize)
    : AP4_CencSingleSampleDecrypter(nullptr)
    , m_cipher(nullptr)
{
    // Create AES block cipher first
    AP4_BlockCipher* block_cipher = nullptr;
    AP4_Result result = AP4_DefaultBlockCipherFactory::Instance.CreateCipher(
        AP4_BlockCipher::AES_128, 
        AP4_BlockCipher::ENCRYPT, 
        AP4_BlockCipher::CTR, 
        nullptr, 
        key, 
        keySize, 
        block_cipher);
    
    if (AP4_SUCCEEDED(result) && block_cipher)
    {
        // Create CTR stream cipher with 16-byte IV
        m_cipher = new AP4_CtrStreamCipher(block_cipher, 16);
    }
    else
    {
        Log(SSD::SSD_HOST::LL_ERROR, "Failed to create AES block cipher for ClearKey");
        m_cipher = nullptr;
    }
}

ClearKeySingleSampleDecrypter::~ClearKeySingleSampleDecrypter()
{
    delete m_cipher;
}

AP4_Result ClearKeySingleSampleDecrypter::DecryptSampleData(AP4_UI32 poolid,
                                                          AP4_DataBuffer& data_in,
                                                          AP4_DataBuffer& data_out,
                                                          const AP4_UI08* iv,
                                                          unsigned int subsample_count,
                                                          const AP4_UI16* bytes_of_cleartext_data,
                                                          const AP4_UI32* bytes_of_encrypted_data)
{
    if (!m_cipher)
        return AP4_ERROR_INVALID_STATE;

    // Set the initialization vector
    if (iv)
    {
        m_cipher->SetIV(iv);
    }

    // Prepare output buffer
    data_out.SetDataSize(data_in.GetDataSize());
    
    const AP4_UI08* in = data_in.GetData();
    AP4_UI08* out = data_out.UseData();
    AP4_Size total_size = data_in.GetDataSize();

    if (subsample_count == 0)
    {
        // No subsamples, decrypt entire buffer
        AP4_Size out_size = total_size;
        return m_cipher->ProcessBuffer(in, total_size, out, &out_size, false);
    }

    // Process subsamples
    AP4_Size offset = 0;
    for (unsigned int i = 0; i < subsample_count; i++)
    {
        // Copy clear data as-is
        if (bytes_of_cleartext_data[i] > 0)
        {
            if (offset + bytes_of_cleartext_data[i] > total_size)
                return AP4_ERROR_INVALID_PARAMETERS;
            
            memcpy(out + offset, in + offset, bytes_of_cleartext_data[i]);
            offset += bytes_of_cleartext_data[i];
        }

        // Decrypt encrypted data
        if (bytes_of_encrypted_data[i] > 0)
        {
            if (offset + bytes_of_encrypted_data[i] > total_size)
                return AP4_ERROR_INVALID_PARAMETERS;

            AP4_Size out_size = bytes_of_encrypted_data[i];
            AP4_Result result = m_cipher->ProcessBuffer(in + offset, bytes_of_encrypted_data[i], 
                                                       out + offset, &out_size, false);
            if (AP4_FAILED(result))
                return result;
            
            offset += bytes_of_encrypted_data[i];
        }
    }

    return AP4_SUCCESS;
}