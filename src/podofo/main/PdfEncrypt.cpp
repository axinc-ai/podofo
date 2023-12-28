#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

#include "PdfEncrypt.h"
#include <podofo/private/PdfDeclarationsPrivate.h>

using namespace std;
using namespace PoDoFo;

PoDoFo::PdfEncrypt::~PdfEncrypt()
{
}

std::unique_ptr<PdfEncrypt> PoDoFo::PdfEncrypt::Create(const std::string_view &userPassword, const std::string_view &ownerPassword, PdfPermissions protection, PdfEncryptAlgorithm algorithm, PdfKeyLength keyLength)
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

std::unique_ptr<PdfEncrypt> PoDoFo::PdfEncrypt::CreateFromObject(const PdfObject &obj)
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

std::unique_ptr<PdfEncrypt> PoDoFo::PdfEncrypt::CreateFromEncrypt(const PdfEncrypt &rhs)
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

PdfEncryptAlgorithm PoDoFo::PdfEncrypt::GetEnabledEncryptionAlgorithms()
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

void PoDoFo::PdfEncrypt::SetEnabledEncryptionAlgorithms(PdfEncryptAlgorithm nEncryptionAlgorithms)
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

bool PoDoFo::PdfEncrypt::IsEncryptionEnabled(PdfEncryptAlgorithm algorithm)
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

void PoDoFo::PdfEncrypt::GenerateEncryptionKey(const PdfString &documentId)
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

bool PoDoFo::PdfEncrypt::Authenticate(const std::string_view &password, const PdfString &documentId)
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

bool PoDoFo::PdfEncrypt::IsPrintAllowed() const
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

bool PoDoFo::PdfEncrypt::IsEditAllowed() const
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

bool PoDoFo::PdfEncrypt::IsCopyAllowed() const
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

bool PoDoFo::PdfEncrypt::IsEditNotesAllowed() const
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

bool PoDoFo::PdfEncrypt::IsFillAndSignAllowed() const
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

bool PoDoFo::PdfEncrypt::IsAccessibilityAllowed() const
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

bool PoDoFo::PdfEncrypt::IsDocAssemblyAllowed() const
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

bool PoDoFo::PdfEncrypt::IsHighPrintAllowed() const
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

int PoDoFo::PdfEncrypt::GetKeyLength() const
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

void PoDoFo::PdfEncrypt::EncryptTo(charbuff &out, const bufferview &view, const PdfReference &objref) const
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

void PoDoFo::PdfEncrypt::DecryptTo(charbuff &out, const bufferview &view, const PdfReference &objref) const
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

PoDoFo::PdfEncrypt::PdfEncrypt()
{
}

PoDoFo::PdfEncrypt::PdfEncrypt(const PdfEncrypt &rhs)
{
}

bool PoDoFo::PdfEncrypt::CheckKey(unsigned char key1[32], unsigned char key2[32])
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

#ifdef PODOFO_HAVE_LIBIDN

PoDoFo::PdfEncryptSHABase::PdfEncryptSHABase()
{
}

PoDoFo::PdfEncryptSHABase::PdfEncryptSHABase(const PdfEncrypt &rhs)
{
}

void PoDoFo::PdfEncryptSHABase::CreateEncryptionDictionary(PdfDictionary &dictionary) const
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

bool PoDoFo::PdfEncryptSHABase::Authenticate(const std::string_view &documentID, const std::string_view &password, const bufferview &uValue, const std::string_view &ueValue, const bufferview &oValue, const std::string_view &oeValue, PdfPermissions pValue, const std::string_view &permsValue, int lengthValue, int rValue)
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

void PoDoFo::PdfEncryptSHABase::GenerateInitialVector(unsigned char iv[]) const
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

void PoDoFo::PdfEncryptSHABase::ComputeEncryptionKey()
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

void PoDoFo::PdfEncryptSHABase::ComputeHash(const unsigned char *pswd, unsigned pswdLen, unsigned char salt[8], unsigned char uValue[48], unsigned char hashValue[32])
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

void PoDoFo::PdfEncryptSHABase::ComputeUserKey(const unsigned char *userpswd, unsigned len)
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

void PoDoFo::PdfEncryptSHABase::ComputeOwnerKey(const unsigned char *userpswd, unsigned len)
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

void PoDoFo::PdfEncryptSHABase::PreprocessPassword(const std::string_view &password, unsigned char *outBuf, unsigned &len)
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

#endif // PODOFO_HAVE_LIBIDN

PoDoFo::PdfEncryptAESBase::~PdfEncryptAESBase()
{
}

PoDoFo::PdfEncryptAESBase::PdfEncryptAESBase()
{
}

void PoDoFo::PdfEncryptAESBase::BaseDecrypt(const unsigned char *key, unsigned keylen, const unsigned char *iv, const unsigned char *textin, size_t textlen, unsigned char *textout, size_t &textoutlen) const
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

void PoDoFo::PdfEncryptAESBase::BaseEncrypt(const unsigned char *key, unsigned keylen, const unsigned char *iv, const unsigned char *textin, size_t textlen, unsigned char *textout, size_t textoutlen) const
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

PoDoFo::PdfEncryptRC4Base::~PdfEncryptRC4Base()
{
}

PoDoFo::PdfEncryptRC4Base::PdfEncryptRC4Base()
{
}

void PoDoFo::PdfEncryptRC4Base::RC4(const unsigned char *key, unsigned keylen, const unsigned char *textin, size_t textlen, unsigned char *textout, size_t textoutlen) const
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

PoDoFo::PdfEncryptMD5Base::PdfEncryptMD5Base()
{
}

PoDoFo::PdfEncryptMD5Base::PdfEncryptMD5Base(const PdfEncrypt &rhs)
{
}

void PoDoFo::PdfEncryptMD5Base::CreateEncryptionDictionary(PdfDictionary &dictionary) const
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

PdfString PoDoFo::PdfEncryptMD5Base::GetMD5String(const unsigned char *buffer, unsigned length)
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

void PoDoFo::PdfEncryptMD5Base::GetMD5Binary(const unsigned char *data, unsigned length, unsigned char *digest)
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

bool PoDoFo::PdfEncryptMD5Base::Authenticate(const std::string_view &documentID, const std::string_view &password, const bufferview &uValue, const bufferview &oValue, PdfPermissions pValue, int lengthValue, int rValue)
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

void PoDoFo::PdfEncryptMD5Base::GenerateInitialVector(unsigned char iv[]) const
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

void PoDoFo::PdfEncryptMD5Base::ComputeOwnerKey(const unsigned char userPad[32], const unsigned char ownerPad[32], int keylength, int revision, bool authenticate, unsigned char ownerKey[32])
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

void PoDoFo::PdfEncryptMD5Base::PadPassword(const std::string_view &password, unsigned char pswd[32])
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

void PoDoFo::PdfEncryptMD5Base::ComputeEncryptionKey(const std::string_view &documentID, const unsigned char userPad[32], const unsigned char ownerKey[32], PdfPermissions pValue, PdfKeyLength keyLength, int revision, unsigned char userKey[32], bool encryptMetadata)
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

void PoDoFo::PdfEncryptMD5Base::CreateObjKey(unsigned char objkey[16], unsigned &pnKeyLen, const PdfReference &objref) const
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

PoDoFo::PdfEncryptAESV2::PdfEncryptAESV2(PdfString oValue, PdfString uValue, PdfPermissions pValue, bool bEncryptMetadata)
{
}

PoDoFo::PdfEncryptAESV2::PdfEncryptAESV2(const std::string_view &userPassword, const std::string_view &ownerPassword, PdfPermissions protection)
{
}

PoDoFo::PdfEncryptAESV2::PdfEncryptAESV2(const PdfEncrypt &rhs)
{
}

std::unique_ptr<InputStream> PoDoFo::PdfEncryptAESV2::CreateEncryptionInputStream(InputStream &inputStream, size_t inputLen, const PdfReference &objref)
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

std::unique_ptr<OutputStream> PoDoFo::PdfEncryptAESV2::CreateEncryptionOutputStream(OutputStream &outputStream, const PdfReference &objref)
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

void PoDoFo::PdfEncryptAESV2::Encrypt(const char *inStr, size_t inLen, const PdfReference &objref, char *outStr, size_t outLen) const
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

void PoDoFo::PdfEncryptAESV2::Decrypt(const char *inStr, size_t inLen, const PdfReference &objref, char *outStr, size_t &outLen) const
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

size_t PoDoFo::PdfEncryptAESV2::CalculateStreamOffset() const
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

size_t PoDoFo::PdfEncryptAESV2::CalculateStreamLength(size_t length) const
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

void PoDoFo::PdfEncryptAESV2::GenerateEncryptionKey(const std::string_view &documentId)
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

bool PoDoFo::PdfEncryptAESV2::Authenticate(const std::string_view &password, const std::string_view &documentId)
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

#ifdef PODOFO_HAVE_LIBIDN

PoDoFo::PdfEncryptAESV3::PdfEncryptAESV3(PdfString oValue, PdfString oeValue, PdfString uValue, PdfString ueValue, PdfPermissions pValue, PdfString permsValue, PdfAESV3Revision rev)
{
}

PoDoFo::PdfEncryptAESV3::PdfEncryptAESV3(const std::string_view &userPassword, const std::string_view &ownerPassword, PdfAESV3Revision rev, PdfPermissions protection)
{
}

PoDoFo::PdfEncryptAESV3::PdfEncryptAESV3(const PdfEncrypt &rhs)
{
}

std::unique_ptr<InputStream> PoDoFo::PdfEncryptAESV3::CreateEncryptionInputStream(InputStream &inputStream, size_t inputLen, const PdfReference &objref)
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

std::unique_ptr<OutputStream> PoDoFo::PdfEncryptAESV3::CreateEncryptionOutputStream(OutputStream &outputStream, const PdfReference &objref)
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

void PoDoFo::PdfEncryptAESV3::Encrypt(const char *inStr, size_t inLen, const PdfReference &objref, char *outStr, size_t outLen) const
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

void PoDoFo::PdfEncryptAESV3::Decrypt(const char *inStr, size_t inLen, const PdfReference &objref, char *outStr, size_t &outLen) const
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

size_t PoDoFo::PdfEncryptAESV3::CalculateStreamOffset() const
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

size_t PoDoFo::PdfEncryptAESV3::CalculateStreamLength(size_t length) const
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

bool PoDoFo::PdfEncryptAESV3::Authenticate(const std::string_view &password, const std::string_view &documentId)
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

void PoDoFo::PdfEncryptAESV3::GenerateEncryptionKey(const std::string_view &documentId)
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

#endif // PODOFO_HAVE_LIBIDN

PoDoFo::PdfEncryptRC4::PdfEncryptRC4(PdfString oValue, PdfString uValue, PdfPermissions pValue, int rValue, PdfEncryptAlgorithm algorithm, int length, bool encryptMetadata)
{
}

PoDoFo::PdfEncryptRC4::PdfEncryptRC4(const std::string_view &userPassword, const std::string_view &ownerPassword, PdfPermissions protection, PdfEncryptAlgorithm algorithm, PdfKeyLength keyLength)
{
}

PoDoFo::PdfEncryptRC4::PdfEncryptRC4(const PdfEncrypt &rhs)
{
}

void PoDoFo::PdfEncryptRC4::Encrypt(const char *inStr, size_t inLen, const PdfReference &objref, char *outStr, size_t outLen) const
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

void PoDoFo::PdfEncryptRC4::Decrypt(const char *inStr, size_t inLen, const PdfReference &objref, char *outStr, size_t &outLen) const
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

std::unique_ptr<InputStream> PoDoFo::PdfEncryptRC4::CreateEncryptionInputStream(InputStream &inputStream, size_t inputLen, const PdfReference &objref)
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

std::unique_ptr<OutputStream> PoDoFo::PdfEncryptRC4::CreateEncryptionOutputStream(OutputStream &outputStream, const PdfReference &objref)
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

size_t PoDoFo::PdfEncryptRC4::CalculateStreamOffset() const
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

size_t PoDoFo::PdfEncryptRC4::CalculateStreamLength(size_t length) const
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

void PoDoFo::PdfEncryptRC4::GenerateEncryptionKey(const std::string_view &documentId)
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

bool PoDoFo::PdfEncryptRC4::Authenticate(const std::string_view &password, const std::string_view &documentId)
{
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

#pragma GCC diagnostic pop