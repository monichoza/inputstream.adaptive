# ClearKey DRM Implementation for inputstream.adaptive

## Overview

This implementation adds support for W3C ClearKey DRM to the inputstream.adaptive Kodi addon. ClearKey is an unencrypted key system that allows for testing and development of DRM-protected content without requiring proprietary DRM systems.

## Files Added/Modified

### New Files
- `src/clearkey_decrypter.h` - ClearKey decrypter interface and class definitions
- `src/clearkey_decrypter.cpp` - ClearKey decrypter implementation

### Modified Files
- `src/main.cpp` - Added ClearKey support to GetSupportedDecrypterURN() and DisposeDecrypter()
- `src/helpers.h` - Added helper function declarations for ClearKey
- `src/helpers.cpp` - Added helper function implementations
- `src/SSD_dll.h` - Added missing includes for standard types
- `CMakeLists.txt` - Added ClearKey source files to build

## Implementation Details

### ClearKey System ID
- Uses the standard W3C ClearKey system ID: `e2719d58-a985-b3c9-781a-b030af78d30e`
- Supports the URN: `urn:uuid:e2719d58-a985-b3c9-781a-b030af78d30e`

### Key Features

1. **License Format Support**
   - JSON Web Key (JWK) format as per W3C EME specification
   - Simple key:value format for testing (kid:key pairs)

2. **Key Processing**
   - Base64url decoding for keys and key IDs
   - Hex string support for simple key format
   - Automatic key ID to key mapping

3. **Encryption Support**
   - AES-128-CTR decryption using Bento4 library
   - Subsample decryption for partially encrypted content
   - Full sample decryption for completely encrypted content

4. **Integration**
   - Built-in decrypter (no external library required)
   - Seamless integration with existing SSD_DECRYPTER interface
   - Automatic fallback to external decrypters if ClearKey not requested

### Usage

The ClearKey implementation is automatically available when the license type is set to `org.w3.clearkey`. No additional configuration is required.

#### License Formats Supported

1. **JSON Web Key (JWK) format:**
```json
{
  "keys": [
    {
      "kty": "oct",
      "kid": "base64url-encoded-key-id",
      "k": "base64url-encoded-key"
    }
  ]
}
```

2. **Simple key:value format:**
```
key-id-hex:key-hex
```

### Technical Architecture

- `ClearKeyDecrypter` - Main decrypter class implementing SSD_DECRYPTER interface
- `ClearKeySingleSampleDecrypter` - Sample decrypter implementing AP4_CencSingleSampleDecrypter
- Helper functions for base64url and hex decoding
- Integration with Bento4 AES-CTR cipher for actual decryption

### Testing

The implementation has been tested with:
- ✓ Compilation without errors
- ✓ Helper function validation (hex/base64url decoding)
- ✓ Integration with existing build system

## Benefits

1. **Development & Testing** - Allows testing DRM workflows without proprietary systems
2. **Standards Compliance** - Implements W3C ClearKey specification
3. **No Dependencies** - Built-in implementation, no external libraries needed
4. **Seamless Integration** - Works with existing inputstream.adaptive architecture

## Future Enhancements

- Support for additional key formats
- Enhanced error reporting and logging
- Performance optimizations for large content
- Extended test coverage

## Compatibility

This implementation is compatible with:
- W3C Encrypted Media Extensions (EME) specification
- Common Encryption (CENC) standard
- Existing inputstream.adaptive DRM framework
- Kodi media player architecture