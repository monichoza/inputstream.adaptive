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

#pragma once

#include "SSD_dll.h"
#include "Ap4.h"
#include <map>
#include <string>
#include <vector>

class ClearKeyDecrypter : public SSD::SSD_DECRYPTER
{
public:
    ClearKeyDecrypter();
    virtual ~ClearKeyDecrypter();

    // SSD_DECRYPTER interface
    virtual const char* SelectKeySytem(const char* keySystem) override;
    virtual bool OpenDRMSystem(const char* licenseURL, const AP4_DataBuffer& serverCertificate, const uint8_t config) override;
    virtual AP4_CencSingleSampleDecrypter* CreateSingleSampleDecrypter(AP4_DataBuffer& pssh, const char* optionalKeyParameter, const uint8_t* defaultkeyid) override;
    virtual void DestroySingleSampleDecrypter(AP4_CencSingleSampleDecrypter* decrypter) override;
    virtual void GetCapabilities(AP4_CencSingleSampleDecrypter* decrypter, const uint8_t* keyid, uint32_t media, SSD_DECRYPTER::SSD_CAPS& caps) override;
    virtual bool HasLicenseKey(AP4_CencSingleSampleDecrypter* decrypter, const uint8_t* keyid) override;
    virtual bool OpenVideoDecoder(AP4_CencSingleSampleDecrypter* decrypter, const SSD::SSD_VIDEOINITDATA* initData) override;
    virtual SSD::SSD_DECODE_RETVAL DecodeVideo(void* instance, SSD::SSD_SAMPLE* sample, SSD::SSD_PICTURE* picture) override;
    virtual void ResetVideo() override;

private:
    struct KeyInfo {
        std::vector<uint8_t> keyId;
        std::vector<uint8_t> key;
    };

    bool ParseClearKeyLicense(const std::string& licenseData);
    bool ParseJSONKeys(const std::string& jsonData);
    const KeyInfo* FindKey(const uint8_t* keyId) const;

    std::vector<KeyInfo> m_keys;
    std::string m_licenseUrl;
    bool m_initialized;
};

class ClearKeySingleSampleDecrypter : public AP4_CencSingleSampleDecrypter
{
public:
    ClearKeySingleSampleDecrypter(const uint8_t* key, AP4_Size keySize);
    virtual ~ClearKeySingleSampleDecrypter();

    virtual AP4_Result DecryptSampleData(AP4_UI32 poolid,
                                       AP4_DataBuffer& data_in,
                                       AP4_DataBuffer& data_out,
                                       const AP4_UI08* iv,
                                       unsigned int subsample_count,
                                       const AP4_UI16* bytes_of_cleartext_data,
                                       const AP4_UI32* bytes_of_encrypted_data) override;

private:
    AP4_StreamCipher* m_cipher;
};