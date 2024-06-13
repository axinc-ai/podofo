#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

#include "PdfEncrypt.h"
#include <podofo/private/PdfDeclarationsPrivate.h>

#include "PdfDictionary.h"
#include "PdfFilter.h"

#include <podofo/auxiliary/AES.h>

#include <boost/uuid/detail/md5.hpp>
#include <boost/algorithm/hex.hpp>
using boost::uuids::detail::md5;

# define MD5_DIGEST_LENGTH 16

# define DUMP_API_CALL
//# define DUMP_API_CALL printf("%s %d\n", __FUNCTION__, __LINE__);

using namespace std;
using namespace PoDoFo;

#ifdef PODOFO_HAVE_LIBIDN
PdfEncryptAlgorithm PdfEncrypt::s_EnabledEncryptionAlgorithms =
PdfEncryptAlgorithm::RC4V1 |
PdfEncryptAlgorithm::RC4V2 |
PdfEncryptAlgorithm::AESV2 |
PdfEncryptAlgorithm::AESV3 |
PdfEncryptAlgorithm::AESV3R6;
#else // PODOFO_HAVE_LIBIDN
PdfEncryptAlgorithm PdfEncrypt::s_EnabledEncryptionAlgorithms =
PdfEncryptAlgorithm::RC4V1 |
PdfEncryptAlgorithm::RC4V2 |
PdfEncryptAlgorithm::AESV2;
#endif // PODOFO_HAVE_LIBIDN

#define AES_IV_LENGTH 16

static void MD5Final(unsigned char * dst, unsigned char *src){
    for (int i = 0; i < MD5_DIGEST_LENGTH; i+=4){
        dst[i + 0] = src [i + 3];
        dst[i + 1] = src [i + 2];
        dst[i + 2] = src [i + 1];
        dst[i + 3] = src [i + 0];
    }
}


/** A class that can encrypt/decrpyt streamed data block wise
 *  This is used in the input and output stream encryption implementation.
 *  Only the RC4 encryption algorithm is supported
 */
class PdfRC4Stream
{
public:
    PdfRC4Stream(unsigned char rc4key[256], unsigned char rc4last[256],
        unsigned char* key, unsigned keylen) :
        m_a(0), m_b(0)
    {
        size_t i;
        size_t j;
        size_t t;

        if (std::memcmp(key, rc4key, keylen) != 0)
        {
            for (i = 0; i < 256; i++)
                m_rc4[i] = static_cast<unsigned char>(i);

            j = 0;
            for (i = 0; i < 256; i++)
            {
                t = static_cast<size_t>(m_rc4[i]);
                j = (j + t + static_cast<size_t>(key[i % keylen])) % 256;
                m_rc4[i] = m_rc4[j];
                m_rc4[j] = static_cast<unsigned char>(t);
            }

            std::memcpy(rc4key, key, keylen);
            std::memcpy(rc4last, m_rc4, 256);
        }
        else
        {
            std::memcpy(m_rc4, rc4last, 256);
        }
    }

    ~PdfRC4Stream()
    {
    }

    /** Encrypt or decrypt a block
     *
     *  \param buffer the input/output buffer. Data is read from this buffer and also stored here
     *  \param len    the size of the buffer
     */
    size_t Encrypt(char* buffer, size_t len)
    {
        unsigned char k;
        int t;

        // Do not encode data with no length
        if (len == 0)
            return len;

        for (size_t i = 0; i < len; i++)
        {
            m_a = (m_a + 1) % 256;
            t = m_rc4[m_a];
            m_b = (m_b + t) % 256;

            m_rc4[m_a] = m_rc4[m_b];
            m_rc4[m_b] = static_cast<unsigned char>(t);

            k = m_rc4[(m_rc4[m_a] + m_rc4[m_b]) % 256];
            buffer[i] = buffer[i] ^ k;
        }

        return len;
    }

private:
    unsigned char m_rc4[256];

    int m_a;
    int m_b;

};

/** An InputStream that decrypts all data read
 *  using the RC4 encryption algorithm
 */
class PdfRC4InputStream : public InputStream
{
public:
    PdfRC4InputStream(InputStream& inputStream, size_t inputLen, unsigned char rc4key[256], unsigned char rc4last[256],
        unsigned char* key, unsigned keylen) :
        m_InputStream(&inputStream),
        m_inputLen(inputLen),
        m_stream(rc4key, rc4last, key, keylen) { }

protected:
    size_t readBuffer(char* buffer, size_t size, bool& eof) override
    {
        // CHECK-ME: The code has never been tested after refactor
        // If it's correct, remove this warning
        bool streameof;
        size_t count = ReadBuffer(*m_InputStream, buffer, std::min(size, m_inputLen), streameof);
        m_inputLen -= count;
        eof = streameof || m_inputLen == 0;
        return m_stream.Encrypt(buffer, count);
    }

private:
    InputStream* m_InputStream;
    size_t m_inputLen;
    PdfRC4Stream m_stream;
};

/** A PdfAESInputStream that decrypts all data read
 *  using the AES encryption algorithm
 */
class PdfAESInputStream : public InputStream
{
public:
    PdfAESInputStream(InputStream& inputStream, size_t inputLen, unsigned char* key, unsigned keylen) :
        m_InputStream(&inputStream),
        m_inputLen(inputLen),
        m_inputEof(false),
        m_init(true),
        m_keyLen(keylen),
        m_drainLeft(0)
    {
        std::memcpy(this->m_key, key, keylen);
    }

protected:
    size_t readBuffer(char* buffer, size_t len, bool& eof) override
    {
        int outlen = 0;
        size_t read;

        // if (m_inputEof)
        //     goto DrainBuffer;

        int rc;
        if (m_init)
        {
            // Read the initialization vector separately first
            char iv[AES_IV_LENGTH];
            bool streameof;
            read = ReadBuffer(*m_InputStream, iv, AES_IV_LENGTH, streameof);
            if (read != AES_IV_LENGTH)
                PODOFO_RAISE_ERROR_INFO(PdfErrorCode::UnexpectedEOF, "Can't read enough bytes for AES IV");

            switch (m_keyLen)
            {
                case (size_t)PdfKeyLength::L128 / 8:
                {
                    m_aes = AES(AESKeyLength::AES_128);
                    break;
                }
#ifdef PODOFO_HAVE_LIBIDN
                case (size_t)PdfKeyLength::L256 / 8:
                {
                    m_aes = AES(AESKeyLength::AES_256);
                    break;
                }
#endif
                default:
                    PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Invalid AES key length");
            }

            m_aes.DecryptCBCInit(m_key, (unsigned char*)iv);

            m_inputLen -= AES_IV_LENGTH;
            m_init = false;
        }

        bool streameof;
        read = ReadBuffer(*m_InputStream, buffer, std::min(len, m_inputLen), streameof);
        m_inputLen -= read;

        unsigned char *tempBuffer = m_aes.DecryptCBC((unsigned char*)buffer, (unsigned int)read);
        outlen = read;

        PODOFO_ASSERT((size_t)outlen <= len);
        std::memcpy(buffer, tempBuffer, (size_t)outlen);

        delete[] tempBuffer;

        if (m_inputLen == 0 || streameof)
        {
            uint8_t paddingLen = buffer[outlen - 1];
            outlen -= paddingLen;

            eof = true;
            return outlen;
        }

        eof = false;
        return outlen;
    }

private:
    // EVP_CIPHER_CTX* m_ctx;
    InputStream* m_InputStream;
    size_t m_inputLen;
    bool m_inputEof;
    bool m_init;
    unsigned char m_key[32];
    unsigned m_keyLen;
    vector<unsigned char> m_tempBuffer;
    size_t m_drainLeft;
    AES m_aes;
};

PoDoFo::PdfEncrypt::~PdfEncrypt()
{
}

std::unique_ptr<PdfEncrypt> PoDoFo::PdfEncrypt::Create(const std::string_view &userPassword, const std::string_view &ownerPassword, PdfPermissions protection, PdfEncryptAlgorithm algorithm, PdfKeyLength keyLength)
{
    DUMP_API_CALL
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

std::unique_ptr<PdfEncrypt> PoDoFo::PdfEncrypt::CreateFromObject(const PdfObject &encryptObj)
{
    DUMP_API_CALL

    if (!encryptObj.GetDictionary().HasKey(PdfName::KeyFilter) ||
        encryptObj.GetDictionary().GetKey(PdfName::KeyFilter)->GetName() != "Standard")
    {
        if (encryptObj.GetDictionary().HasKey(PdfName::KeyFilter))
            PODOFO_RAISE_ERROR_INFO(PdfErrorCode::UnsupportedFilter, "Unsupported encryption filter: {}",
                encryptObj.GetDictionary().GetKey(PdfName::KeyFilter)->GetName().GetString());
        else
            PODOFO_RAISE_ERROR_INFO(PdfErrorCode::UnsupportedFilter, "Encryption dictionary does not have a key /Filter");
    }

    int lV;
    int64_t length;
    int rValue;
    PdfPermissions pValue;
    PdfString oValue;
    PdfString uValue;
    PdfName cfmName;
    bool encryptMetadata = true;

    try
    {
        lV = static_cast<int>(encryptObj.GetDictionary().MustGetKey("V").GetNumber());
        rValue = static_cast<int>(encryptObj.GetDictionary().MustGetKey("R").GetNumber());

        pValue = static_cast<PdfPermissions>(encryptObj.GetDictionary().MustGetKey("P").GetNumber());

        oValue = encryptObj.GetDictionary().MustGetKey("O").GetString();
        uValue = encryptObj.GetDictionary().MustGetKey("U").GetString();

        if (encryptObj.GetDictionary().HasKey("Length"))
            length = encryptObj.GetDictionary().GetKey("Length")->GetNumber();
        else
            length = 0;

        const PdfObject* encryptMetadataObj = encryptObj.GetDictionary().GetKey("EncryptMetadata");
        if (encryptMetadataObj != nullptr && encryptMetadataObj->IsBool())
            encryptMetadata = encryptMetadataObj->GetBool();

        auto stmfObj = encryptObj.GetDictionary().GetKey("StmF");
        if (stmfObj != nullptr && stmfObj->IsName())
        {
            const PdfObject* obj = encryptObj.GetDictionary().GetKey("CF");
            if (obj != nullptr && obj->IsDictionary())
            {
                obj = obj->GetDictionary().GetKey(stmfObj->GetName());
                if (obj != nullptr && obj->IsDictionary())
                {
                    obj = obj->GetDictionary().GetKey("CFM");
                    if (obj != nullptr && obj->IsName())
                        cfmName = obj->GetName();
                }
            }
        }
    }
    catch (PdfError& e)
    {
        PODOFO_PUSH_FRAME_INFO(e, "Invalid or missing key in encryption dictionary");
        throw e;
    }

    if ((lV == 1) && (rValue == 2 || rValue == 3)
        && PdfEncrypt::IsEncryptionEnabled(PdfEncryptAlgorithm::RC4V1))
    {
        return unique_ptr<PdfEncrypt>(new PdfEncryptRC4(oValue, uValue, pValue, rValue, PdfEncryptAlgorithm::RC4V1, (int)PdfKeyLength::L40, encryptMetadata));
    }
    else if ((((lV == 2) && (rValue == 3)) || cfmName == "V2")
        && PdfEncrypt::IsEncryptionEnabled(PdfEncryptAlgorithm::RC4V2))
    {
        // length is int64_t. Please make changes in encryption algorithms
        // Check key length length here to prevent
        // stack-based buffer over-read later in this file
        if (length > MD5_DIGEST_LENGTH * CHAR_BIT) // length in bits, md5 in bytes
        {
            PODOFO_RAISE_ERROR_INFO(PdfErrorCode::ValueOutOfRange, "Given key length too large for MD5");
        }
        return unique_ptr<PdfEncrypt>(new PdfEncryptRC4(oValue, uValue, pValue, rValue, PdfEncryptAlgorithm::RC4V2, static_cast<int>(length), encryptMetadata));
    }
    else
    {
        if ((lV == 4) && (rValue == 4)
            && PdfEncrypt::IsEncryptionEnabled(PdfEncryptAlgorithm::AESV2))
        {
            return unique_ptr<PdfEncrypt>(new PdfEncryptAESV2(oValue, uValue, pValue, encryptMetadata));
        }
#ifdef PODOFO_HAVE_LIBIDN
        else if ((lV == 5) && (
            (rValue == 5 && PdfEncrypt::IsEncryptionEnabled(PdfEncryptAlgorithm::AESV3))
            || (rValue == 6 && PdfEncrypt::IsEncryptionEnabled(PdfEncryptAlgorithm::AESV3R6))))
        {
            PdfString permsValue = encryptObj.GetDictionary().MustFindKey("Perms").GetString();
            PdfString oeValue = encryptObj.GetDictionary().MustFindKey("OE").GetString();
            PdfString ueValue = encryptObj.GetDictionary().MustFindKey("UE").GetString();

            return unique_ptr<PdfEncrypt>(new PdfEncryptAESV3(oValue, oeValue, uValue,
                ueValue, pValue, permsValue, (PdfAESV3Revision)rValue));
        }
#endif // PODOFO_HAVE_LIBIDN
        else
        {
            PODOFO_RAISE_ERROR_INFO(PdfErrorCode::UnsupportedFilter, "Unsupported encryption method Version={} Revision={}", lV , rValue);
        }
    }
}

std::unique_ptr<PdfEncrypt> PoDoFo::PdfEncrypt::CreateFromEncrypt(const PdfEncrypt &rhs)
{
    DUMP_API_CALL

    switch (rhs.m_Algorithm)
    {
        case PdfEncryptAlgorithm::RC4V1:
        case PdfEncryptAlgorithm::RC4V2:
            return unique_ptr<PdfEncrypt>(new PdfEncryptRC4(rhs));
        case PdfEncryptAlgorithm::AESV2:
            return unique_ptr<PdfEncrypt>(new PdfEncryptAESV2(rhs));
#ifdef PODOFO_HAVE_LIBIDN
        case PdfEncryptAlgorithm::AESV3:
        case PdfEncryptAlgorithm::AESV3R6:
            return unique_ptr<PdfEncrypt>(new PdfEncryptAESV3(rhs));
#endif // PODOFO_HAVE_LIBIDN
        default:
            PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InvalidEnumValue, "Invalid algorithm");
    }
}

PdfEncryptAlgorithm PoDoFo::PdfEncrypt::GetEnabledEncryptionAlgorithms()
{
    DUMP_API_CALL
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

void PoDoFo::PdfEncrypt::SetEnabledEncryptionAlgorithms(PdfEncryptAlgorithm nEncryptionAlgorithms)
{
    DUMP_API_CALL
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

bool PoDoFo::PdfEncrypt::IsEncryptionEnabled(PdfEncryptAlgorithm algorithm)
{
    DUMP_API_CALL
    return (PdfEncrypt::s_EnabledEncryptionAlgorithms & algorithm) != PdfEncryptAlgorithm::None;
}

void PoDoFo::PdfEncrypt::GenerateEncryptionKey(const PdfString &documentId)
{
    DUMP_API_CALL
    GenerateEncryptionKey(documentId.GetRawData());
}

bool PoDoFo::PdfEncrypt::Authenticate(const std::string_view &password, const PdfString &documentId)
{
    DUMP_API_CALL
    return Authenticate(password, documentId.GetRawData());
}

bool PoDoFo::PdfEncrypt::IsPrintAllowed() const
{
    DUMP_API_CALL
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

bool PoDoFo::PdfEncrypt::IsEditAllowed() const
{
    DUMP_API_CALL
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

bool PoDoFo::PdfEncrypt::IsCopyAllowed() const
{
    DUMP_API_CALL
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

bool PoDoFo::PdfEncrypt::IsEditNotesAllowed() const
{
    DUMP_API_CALL
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

bool PoDoFo::PdfEncrypt::IsFillAndSignAllowed() const
{
    DUMP_API_CALL
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

bool PoDoFo::PdfEncrypt::IsAccessibilityAllowed() const
{
    DUMP_API_CALL
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

bool PoDoFo::PdfEncrypt::IsDocAssemblyAllowed() const
{
    DUMP_API_CALL
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

bool PoDoFo::PdfEncrypt::IsHighPrintAllowed() const
{
    DUMP_API_CALL
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

int PoDoFo::PdfEncrypt::GetKeyLength() const
{
    DUMP_API_CALL
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

void PoDoFo::PdfEncrypt::EncryptTo(charbuff &out, const bufferview &view, const PdfReference &objref) const
{
    DUMP_API_CALL
    size_t outputLen = this->CalculateStreamLength(view.size());
    out.resize(outputLen);
    this->Encrypt(view.data(), view.size(), objref, out.data(), outputLen);
}

void PoDoFo::PdfEncrypt::DecryptTo(charbuff &out, const bufferview &view, const PdfReference &objref) const
{
    // FIX-ME: The following clearly seems hardcoded for AES
    // It was found like this in PdfString and PdfTokenizer
    // Fix it so it will allocate the exact amount of memory
    // needed, including RC4
    size_t outBufferLen = view.size() - this->CalculateStreamOffset();
    out.resize(outBufferLen + 16 - (outBufferLen % 16));
    this->Decrypt(view.data(), view.size(), objref, out.data(), outBufferLen);
    out.resize(outBufferLen);
    out.shrink_to_fit();
}

PoDoFo::PdfEncrypt::PdfEncrypt() :
    m_Algorithm(PdfEncryptAlgorithm::AESV2),
    m_eKeyLength(PdfKeyLength::L128),
    m_keyLength(0),
    m_rValue(0),
    m_pValue(PdfPermissions::None),
    m_EncryptMetadata(true)
{
    DUMP_API_CALL
    memset(m_uValue, 0, 48);
    memset(m_oValue, 0, 48);
    memset(m_encryptionKey, 0, 32);
}

PoDoFo::PdfEncrypt::PdfEncrypt(const PdfEncrypt &rhs)
{
    DUMP_API_CALL
    m_Algorithm = rhs.m_Algorithm;
    m_eKeyLength = rhs.m_eKeyLength;

    m_pValue = rhs.m_pValue;
    m_rValue = rhs.m_rValue;

    m_keyLength = rhs.m_keyLength;

    m_documentId = rhs.m_documentId;
    m_userPass = rhs.m_userPass;
    m_ownerPass = rhs.m_ownerPass;
    m_EncryptMetadata = rhs.m_EncryptMetadata;
}

bool PoDoFo::PdfEncrypt::CheckKey(unsigned char key1[32], unsigned char key2[32])
{
    DUMP_API_CALL

    // Check whether the right password had been given
    bool success = true;
    for (unsigned k = 0; success && k < m_keyLength; k++)
        success = success && (key1[k] == key2[k]);
    
    return success;
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
    DUMP_API_CALL
}

PoDoFo::PdfEncryptAESBase::PdfEncryptAESBase()
{
    DUMP_API_CALL
}

void PoDoFo::PdfEncryptAESBase::BaseDecrypt(const unsigned char *key, unsigned keylen, const unsigned char *iv, const unsigned char *textin, size_t textlen, unsigned char *textout, size_t &textoutlen) const
{
    DUMP_API_CALL

    AES aes(AESKeyLength::AES_128);
    unsigned char *tmp = aes.DecryptCBC(textin, textlen, key, iv);
    uint8_t paddingLen = tmp[textlen - 1];
    textoutlen = textlen - paddingLen;
    std::memcpy(textout, tmp, textoutlen);

    delete[] tmp;
}

void PoDoFo::PdfEncryptAESBase::BaseEncrypt(const unsigned char *key, unsigned keylen, const unsigned char *iv, const unsigned char *textin, size_t textlen, unsigned char *textout, size_t textoutlen) const
{
    DUMP_API_CALL
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

PoDoFo::PdfEncryptRC4Base::~PdfEncryptRC4Base()
{
    DUMP_API_CALL
}

PoDoFo::PdfEncryptRC4Base::PdfEncryptRC4Base()
{
    DUMP_API_CALL
}

typedef struct {
    unsigned char s[256];
    unsigned char i;
    unsigned char j;
} RC4_STATE;

void rc4_init(RC4_STATE* state, const unsigned char* key, unsigned keylen) {
    unsigned char tmp;
    int i;
    unsigned char j = 0;

    for (i = 0; i < 256; i++) {
        state->s[i] = (unsigned char)i;
    }

    for (i = 0; i < 256; i++) {
        j = (j + state->s[i] + key[i % keylen]) % 256;
        tmp = state->s[i];
        state->s[i] = state->s[j];
        state->s[j] = tmp;
    }

    state->i = 0;
    state->j = 0;
}

void rc4_encrypt(RC4_STATE* state, const unsigned char* textin, size_t textlen, unsigned char* textout) {
    size_t dataOutMoved = 0;

    for (size_t k = 0; k < textlen; k++) {
        state->i = (state->i + 1) % 256;
        state->j = (state->j + state->s[state->i]) % 256;

        unsigned char tmp = state->s[state->i];
        state->s[state->i] = state->s[state->j];
        state->s[state->j] = tmp;

        unsigned char c = (state->s[state->i] + state->s[state->j]) % 256;
        textout[k] = textin[k] ^ state->s[c];
        dataOutMoved++;
    }
}

void PdfEncryptRC4Base::RC4(const unsigned char* key, unsigned keylen,
    const unsigned char* textin, size_t textlen,
    unsigned char* textout, size_t textoutlen) const
{
    if (textlen != textoutlen)
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Error initializing RC4 encryption engine");

    DUMP_API_CALL

    RC4_STATE state;
    rc4_init(&state, key, keylen);
    rc4_encrypt(&state, textin, textlen, textout);
}

PoDoFo::PdfEncryptMD5Base::PdfEncryptMD5Base() : m_rc4key{ }, m_rc4last{ }
{
    DUMP_API_CALL
}

PoDoFo::PdfEncryptMD5Base::PdfEncryptMD5Base(const PdfEncrypt& rhs) : PdfEncrypt(rhs)
{
    DUMP_API_CALL
    const PdfEncrypt* ptr = &rhs;

    std::memcpy(m_uValue, rhs.GetUValue(), sizeof(unsigned char) * 32);
    std::memcpy(m_oValue, rhs.GetOValue(), sizeof(unsigned char) * 32);

    std::memcpy(m_encryptionKey, rhs.GetEncryptionKey(), sizeof(unsigned char) * 16);

    std::memcpy(m_rc4key, static_cast<const PdfEncryptMD5Base*>(ptr)->m_rc4key, sizeof(unsigned char) * 16);
    std::memcpy(m_rc4last, static_cast<const PdfEncryptMD5Base*>(ptr)->m_rc4last, sizeof(unsigned char) * 256);
    m_EncryptMetadata = static_cast<const PdfEncryptMD5Base*>(ptr)->m_EncryptMetadata;
}

void PoDoFo::PdfEncryptMD5Base::CreateEncryptionDictionary(PdfDictionary &dictionary) const
{
    DUMP_API_CALL
    dictionary.AddKey(PdfName::KeyFilter, PdfName("Standard"));

    if (m_Algorithm == PdfEncryptAlgorithm::AESV2 || !m_EncryptMetadata)
    {
        PdfDictionary cf;
        PdfDictionary stdCf;

        if (m_Algorithm == PdfEncryptAlgorithm::RC4V2)
            stdCf.AddKey("CFM", PdfName("V2"));
        else
            stdCf.AddKey("CFM", PdfName("AESV2"));
        stdCf.AddKey("Length", static_cast<int64_t>(16));

        dictionary.AddKey("O", PdfString::FromRaw({ reinterpret_cast<const char*>(this->GetOValue()), 32 }));
        dictionary.AddKey("U", PdfString::FromRaw({ reinterpret_cast<const char*>(this->GetUValue()), 32 }));

        stdCf.AddKey("AuthEvent", PdfName("DocOpen"));
        cf.AddKey("StdCF", stdCf);

        dictionary.AddKey("CF", cf);
        dictionary.AddKey("StrF", PdfName("StdCF"));
        dictionary.AddKey("StmF", PdfName("StdCF"));

        dictionary.AddKey("V", static_cast<int64_t>(4));
        dictionary.AddKey("R", static_cast<int64_t>(4));
        dictionary.AddKey("Length", static_cast<int64_t>(128));
        if (!m_EncryptMetadata)
            dictionary.AddKey("EncryptMetadata", PdfVariant(false));
    }
    else if (m_Algorithm == PdfEncryptAlgorithm::RC4V1)
    {
        dictionary.AddKey("V", static_cast<int64_t>(1));
        // Can be 2 or 3
        dictionary.AddKey("R", static_cast<int64_t>(m_rValue));
    }
    else if (m_Algorithm == PdfEncryptAlgorithm::RC4V2)
    {
        dictionary.AddKey("V", static_cast<int64_t>(2));
        dictionary.AddKey("R", static_cast<int64_t>(3));
        dictionary.AddKey("Length", PdfVariant(static_cast<int64_t>(m_eKeyLength)));
    }

    dictionary.AddKey("O", PdfString::FromRaw({ reinterpret_cast<const char*>(this->GetOValue()), 32 }));
    dictionary.AddKey("U", PdfString::FromRaw({ reinterpret_cast<const char*>(this->GetUValue()), 32 }));
    dictionary.AddKey("P", PdfVariant(static_cast<int64_t>(this->GetPValue())));
}

PdfString PoDoFo::PdfEncryptMD5Base::GetMD5String(const unsigned char *buffer, unsigned length)
{
    DUMP_API_CALL

    char data[MD5_DIGEST_LENGTH] = "";

    GetMD5Binary(buffer, length, reinterpret_cast<unsigned char*>(data));

    return PdfString::FromRaw({ data, MD5_DIGEST_LENGTH });

}

void PoDoFo::PdfEncryptMD5Base::GetMD5Binary(const unsigned char *data, unsigned length, unsigned char *digest)
{
    DUMP_API_CALL
    md5 hash;
    md5::digest_type digest2;
    hash.process_bytes(data, length);
    hash.get_digest(digest2);
    MD5Final(digest, (unsigned char*)digest2);
}

bool PoDoFo::PdfEncryptMD5Base::Authenticate(const std::string_view &documentID, const std::string_view &password, const bufferview &uValue, const bufferview &oValue, PdfPermissions pValue, int lengthValue, int rValue)
{
    DUMP_API_CALL
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

void PoDoFo::PdfEncryptMD5Base::GenerateInitialVector(unsigned char iv[]) const
{
    DUMP_API_CALL
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

void PoDoFo::PdfEncryptMD5Base::ComputeOwnerKey(const unsigned char userPad[32], const unsigned char ownerPad[32], int keylength, int revision, bool authenticate, unsigned char ownerKey[32])
{
    DUMP_API_CALL

    unsigned char mkey[MD5_DIGEST_LENGTH];
    unsigned char digest[MD5_DIGEST_LENGTH];
    int rc;

    md5 hash;
    md5::digest_type digest2;

    /*
    unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (ctx == nullptr || (rc = EVP_DigestInit_ex(ctx.get(), s_SSL.MD5, nullptr)) != 1)
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Error initializing MD5 hashing engine");

    rc = EVP_DigestUpdate(ctx.get(), ownerPad, 32);
    if (rc != 1)
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Error MD5-hashing data");

    rc = EVP_DigestFinal_ex(ctx.get(), digest, nullptr);
    if (rc != 1)
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Error MD5-hashing data");
    */

    hash.process_bytes(ownerPad, 32);
    hash.get_digest(digest2);
    MD5Final(digest, (unsigned char*)digest2);

    if ((revision == 3) || (revision == 4))
    {
        // only use for the input as many bit as the key consists of
        for (int k = 0; k < 50; ++k)
        {
            /*
            rc = EVP_DigestInit_ex(ctx.get(), s_SSL.MD5, nullptr);
            if (rc != 1)
                PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Error initializing MD5 hashing engine");

            rc = EVP_DigestUpdate(ctx.get(), digest, keyLength);
            if (rc != 1)
                PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Error MD5-hashing data");

            rc = EVP_DigestFinal_ex(ctx.get(), digest, nullptr);
            if (rc != 1)
                PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Error MD5-hashing data");
            */

            md5 hash2;
            hash2.process_bytes(ownerPad, 32);
            hash2.get_digest(digest2);
            MD5Final(digest, (unsigned char*)digest2);
        }
        std::memcpy(ownerKey, userPad, 32);
        for (unsigned i = 0; i < 20; ++i)
        {
            for (int j = 0; j < keylength; ++j)
            {
                if (authenticate)
                    mkey[j] = static_cast<unsigned char>(static_cast<unsigned>(digest[j] ^ (19 - i)));
                else
                    mkey[j] = static_cast<unsigned char>(static_cast<unsigned>(digest[j] ^ i));
            }
            RC4(mkey, keylength, ownerKey, 32, ownerKey, 32);
        }
    }
    else
    {
        RC4(digest, 5, userPad, 32, ownerKey, 32);
    }
}

static unsigned char padding[] =
"\x28\xBF\x4E\x5E\x4E\x75\x8A\x41\x64\x00\x4E\x56\xFF\xFA\x01\x08\x2E\x2E\x00\xB6\xD0\x68\x3E\x80\x2F\x0C\xA9\xFE\x64\x53\x69\x7A";

void PoDoFo::PdfEncryptMD5Base::PadPassword(const std::string_view &password, unsigned char pswd[32])
{
    DUMP_API_CALL

    size_t m = password.length();

    if (m > 32) m = 32;

    size_t j;
    size_t p = 0;
    for (j = 0; j < m; j++)
        pswd[p++] = static_cast<unsigned char>(password[j]);

    for (j = 0; p < 32 && j < 32; j++)
        pswd[p++] = padding[j];
}

void PoDoFo::PdfEncryptMD5Base::ComputeEncryptionKey(const std::string_view &documentId, const unsigned char userPad[32], const unsigned char ownerKey[32], PdfPermissions pValue, PdfKeyLength keyLength, int revision, unsigned char userKey[32], bool encryptMetadata)
{
    DUMP_API_CALL

    unsigned j;
    unsigned k;
    m_keyLength = (int)keyLength / 8;
    int rc;

    md5 hash;
    md5::digest_type digest2;

    /*
    unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (ctx == nullptr || (rc = EVP_DigestInit_ex(ctx.get(), s_SSL.MD5, nullptr)) != 1)
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Error initializing MD5 hashing engine");

    rc = EVP_DigestUpdate(ctx.get(), userPad, 32);
    if (rc != 1)
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Error MD5-hashing data");

    rc = EVP_DigestUpdate(ctx.get(), ownerKey, 32);
    if (rc != 1)
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Error MD5-hashing data");
    */

    hash.process_bytes(userPad, 32);
    hash.process_bytes(ownerKey, 32);

    unsigned char ext[4];
    ext[0] = static_cast<unsigned char> (((unsigned)pValue >> 0) & 0xFF);
    ext[1] = static_cast<unsigned char> (((unsigned)pValue >> 8) & 0xFF);
    ext[2] = static_cast<unsigned char> (((unsigned)pValue >> 16) & 0xFF);
    ext[3] = static_cast<unsigned char> (((unsigned)pValue >> 24) & 0xFF);
    
    /*
    rc = EVP_DigestUpdate(ctx.get(), ext, 4);
    if (rc != 1)
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Error MD5-hashing data");
    */
    hash.process_bytes(ext, 4);

    unsigned docIdLength = static_cast<unsigned>(documentId.length());
    vector<unsigned char> docId;
    if (docIdLength > 0)
    {
        docId.resize(docIdLength);
        for (j = 0; j < docIdLength; j++)
        {
            docId[j] = static_cast<unsigned char>(documentId[j]);
        }
        //rc = EVP_DigestUpdate(ctx.get(), docId.data(), docIdLength);
        //if (rc != 1)
        //    PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Error MD5-hashing data");
        hash.process_bytes(docId.data(), docIdLength);
    }

    // If document metadata is not being encrypted, 
    // pass 4 bytes with the value 0xFFFFFFFF to the MD5 hash function.
    if (!encryptMetadata)
    {
        unsigned char noMetaAddition[4] = { 0xFF, 0xFF, 0xFF, 0xFF };
        //rc = EVP_DigestUpdate(ctx.get(), noMetaAddition, 4);
        //if (rc != 1)
        //    PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Error MD5-hashing data");
        hash.process_bytes(noMetaAddition, 4);
    }

    unsigned char digest[MD5_DIGEST_LENGTH];
    //rc = EVP_DigestFinal_ex(ctx.get(), digest, nullptr);
    //if (rc != 1)
    //    PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Error MD5-hashing data");
    hash.get_digest(digest2);
    MD5Final(digest, (unsigned char*)digest2);

    // only use the really needed bits as input for the hash
    if (revision == 3 || revision == 4)
    {
        for (k = 0; k < 50; ++k)
        {
            /*
            rc = EVP_DigestInit_ex(ctx.get(), s_SSL.MD5, nullptr);
            if (rc != 1)
                PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Error initializing MD5 hashing engine");

            rc = EVP_DigestUpdate(ctx.get(), digest, m_keyLength);
            if (rc != 1)
                PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Error MD5-hashing data");

            rc = EVP_DigestFinal_ex(ctx.get(), digest, nullptr);
            if (rc != 1)
                PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Error MD5-hashing data");
            */
            md5 hash2;
            hash2.process_bytes(digest, m_keyLength);
            hash2.get_digest(digest2);
            MD5Final(digest, (unsigned char*)digest2);
        }
    }

    std::memcpy(m_encryptionKey, digest, m_keyLength);

    // Setup user key
    if (revision == 3 || revision == 4)
    {
        md5 hash3;

        //rc = EVP_DigestInit_ex(ctx.get(), s_SSL.MD5, nullptr);
        //if (rc != 1)
        //    PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Error initializing MD5 hashing engine");

        //rc = EVP_DigestUpdate(ctx.get(), padding, 32);
        //if (rc != 1)
        //    PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Error MD5-hashing data");

        hash3.process_bytes(padding, 32);

        if (docId.size() != 0)
        {
            //rc = EVP_DigestUpdate(ctx.get(), docId.data(), docIdLength);
            //if (rc != 1)
            //    PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Error MD5-hashing data");

            hash3.process_bytes(docId.data(), docIdLength);
        }

        //rc = EVP_DigestFinal_ex(ctx.get(), digest, nullptr);
        //if (rc != 1)
        //    PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Error MD5-hashing data");

        hash3.get_digest(digest2);
        MD5Final(digest, (unsigned char*)digest2);

        std::memcpy(userKey, digest, 16);
        for (k = 16; k < 32; k++)
            userKey[k] = 0;

        for (k = 0; k < 20; k++)
        {
            for (j = 0; j < m_keyLength; j++)
            {
                digest[j] = static_cast<unsigned char>(m_encryptionKey[j] ^ k);
            }

            RC4(digest, m_keyLength, userKey, 16, userKey, 16);
        }
    }
    else
    {
        RC4(m_encryptionKey, m_keyLength, padding, 32, userKey, 32);
    }
}

void PoDoFo::PdfEncryptMD5Base::CreateObjKey(unsigned char objkey[16], unsigned &pnKeyLen, const PdfReference &objref) const
{
    DUMP_API_CALL

    const unsigned n = static_cast<unsigned>(objref.ObjectNumber());
    const unsigned g = static_cast<unsigned>(objref.GenerationNumber());

    unsigned nkeylen = m_keyLength + 5;
    unsigned char nkey[MD5_DIGEST_LENGTH + 5 + 4];
    for (unsigned j = 0; j < m_keyLength; j++)
        nkey[j] = m_encryptionKey[j];

    nkey[m_keyLength + 0] = static_cast<unsigned char>(0xFF & n);
    nkey[m_keyLength + 1] = static_cast<unsigned char>(0xFF & (n >> 8));
    nkey[m_keyLength + 2] = static_cast<unsigned char>(0xFF & (n >> 16));
    nkey[m_keyLength + 3] = static_cast<unsigned char>(0xFF & g);
    nkey[m_keyLength + 4] = static_cast<unsigned char>(0xFF & (g >> 8));

    if (m_Algorithm == PdfEncryptAlgorithm::AESV2)
    {
        // AES encryption needs some 'salt'
        nkeylen += 4;
        nkey[m_keyLength + 5] = 0x73;
        nkey[m_keyLength + 6] = 0x41;
        nkey[m_keyLength + 7] = 0x6C;
        nkey[m_keyLength + 8] = 0x54;
    }

    GetMD5Binary(nkey, nkeylen, objkey);
    pnKeyLen = (m_keyLength <= 11) ? m_keyLength + 5 : 16;
}

PoDoFo::PdfEncryptAESV2::PdfEncryptAESV2(PdfString oValue, PdfString uValue, PdfPermissions pValue, bool bEncryptMetadata)
{
    DUMP_API_CALL
    m_pValue = pValue;
    m_Algorithm = PdfEncryptAlgorithm::AESV2;

    m_eKeyLength = PdfKeyLength::L128;
    m_keyLength = (int)PdfKeyLength::L128 / 8;
    m_rValue = 4;
    m_EncryptMetadata = bEncryptMetadata;

    auto& oValueData = oValue.GetRawData();
    if (oValueData.size() < 32)
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InvalidEncryptionDict, "/O value is invalid");

    auto& uValueData = uValue.GetRawData();
    if (uValueData.size() < 32)
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InvalidEncryptionDict, "/U value is invalid");

    std::memcpy(m_oValue, oValueData.data(), 32);
    std::memcpy(m_uValue, uValueData.data(), 32);

    // Init buffers
    std::memset(m_rc4key, 0, 16);
    std::memset(m_rc4last, 0, 256);
    std::memset(m_encryptionKey, 0, 32);
}

PoDoFo::PdfEncryptAESV2::PdfEncryptAESV2(const std::string_view &userPassword, const std::string_view &ownerPassword, PdfPermissions protection)
{
    DUMP_API_CALL
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

PoDoFo::PdfEncryptAESV2::PdfEncryptAESV2(const PdfEncrypt &rhs)
{
    DUMP_API_CALL
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

std::unique_ptr<InputStream> PoDoFo::PdfEncryptAESV2::CreateEncryptionInputStream(InputStream &inputStream, size_t inputLen, const PdfReference &objref)
{
    DUMP_API_CALL
    unsigned char objkey[MD5_DIGEST_LENGTH];
    unsigned keylen;
    this->CreateObjKey(objkey, keylen, objref);
    return unique_ptr<InputStream>(new PdfAESInputStream(inputStream, inputLen, objkey, keylen));
}

std::unique_ptr<OutputStream> PoDoFo::PdfEncryptAESV2::CreateEncryptionOutputStream(OutputStream &outputStream, const PdfReference &objref)
{
    DUMP_API_CALL
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

void PoDoFo::PdfEncryptAESV2::Encrypt(const char *inStr, size_t inLen, const PdfReference &objref, char *outStr, size_t outLen) const
{
    DUMP_API_CALL
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

void PoDoFo::PdfEncryptAESV2::Decrypt(const char *inStr, size_t inLen, const PdfReference &objref, char *outStr, size_t &outLen) const
{
    DUMP_API_CALL
    unsigned char objkey[MD5_DIGEST_LENGTH];
    unsigned keylen;
    CreateObjKey(objkey, keylen, objref);

    size_t offset = CalculateStreamOffset();
    if (inLen <= offset)
    {
        // Is empty
        outLen = 0;
        return;
    }

    this->BaseDecrypt(objkey, keylen, (const unsigned char*)inStr,
        (const unsigned char*)inStr + offset,
        inLen - offset, (unsigned char*)outStr, outLen);
}

size_t PoDoFo::PdfEncryptAESV2::CalculateStreamOffset() const
{
    DUMP_API_CALL
    return AES_IV_LENGTH;
}

size_t PoDoFo::PdfEncryptAESV2::CalculateStreamLength(size_t length) const
{
    DUMP_API_CALL
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

void PoDoFo::PdfEncryptAESV2::GenerateEncryptionKey(const std::string_view &documentId)
{
    DUMP_API_CALL
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

bool PoDoFo::PdfEncryptAESV2::Authenticate(const std::string_view &password, const std::string_view &documentId)
{
    DUMP_API_CALL
    m_documentId = documentId;

    // Pad password
    unsigned char pswd[32];
    PadPassword(password, pswd);

    // Check password: 1) as user password, 2) as owner password
    unsigned char userKey[32];
    ComputeEncryptionKey(m_documentId, pswd, m_oValue, m_pValue, m_eKeyLength, m_rValue, userKey, m_EncryptMetadata);

    bool success = CheckKey(userKey, m_uValue);
    if (success)
    {
        m_userPass = password;
    }
    else
    {
        unsigned char userpswd[32];
        ComputeOwnerKey(m_oValue, pswd, m_keyLength, m_rValue, true, userpswd);
        ComputeEncryptionKey(m_documentId, userpswd, m_oValue, m_pValue, m_eKeyLength, m_rValue, userKey, m_EncryptMetadata);
        success = CheckKey(userKey, m_uValue);

        if (success)
            m_ownerPass = password;
    }

    return success;
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
    DUMP_API_CALL

    m_pValue = pValue;
    m_rValue = rValue;
    m_Algorithm = algorithm;
    m_eKeyLength = static_cast<PdfKeyLength>(length);
    m_keyLength = length / 8;
    m_EncryptMetadata = encryptMetadata;

    auto& oValueData = oValue.GetRawData();
    if (oValueData.size() < 32)
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InvalidEncryptionDict, "/O value is invalid");

    auto& uValueData = uValue.GetRawData();
    if (uValueData.size() < 32)
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InvalidEncryptionDict, "/U value is invalid");

    std::memcpy(m_oValue, oValueData.data(), 32);
    std::memcpy(m_uValue, uValueData.data(), 32);

    // Init buffers
    std::memset(m_rc4key, 0, 16);
    std::memset(m_rc4last, 0, 256);
    std::memset(m_encryptionKey, 0, 32);
}

PoDoFo::PdfEncryptRC4::PdfEncryptRC4(const std::string_view &userPassword, const std::string_view &ownerPassword, PdfPermissions protection, PdfEncryptAlgorithm algorithm, PdfKeyLength keyLength)
{
    DUMP_API_CALL
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

PoDoFo::PdfEncryptRC4::PdfEncryptRC4(const PdfEncrypt &rhs)
    : PdfEncryptMD5Base(rhs)
{
    DUMP_API_CALL
}

void PoDoFo::PdfEncryptRC4::Encrypt(const char *inStr, size_t inLen, const PdfReference &objref, char *outStr, size_t outLen) const
{
    DUMP_API_CALL
    unsigned char objkey[MD5_DIGEST_LENGTH];
    unsigned keylen;
    CreateObjKey(objkey, keylen, objref);
    this->RC4(objkey, keylen, (const unsigned char *)inStr, inLen,
        (unsigned char*)outStr, outLen);
}

void PoDoFo::PdfEncryptRC4::Decrypt(const char *inStr, size_t inLen, const PdfReference &objref, char *outStr, size_t &outLen) const
{
    DUMP_API_CALL
    Encrypt(inStr, inLen, objref, outStr, outLen);
}

std::unique_ptr<InputStream> PoDoFo::PdfEncryptRC4::CreateEncryptionInputStream(InputStream &inputStream, size_t inputLen, const PdfReference &objref)
{
    DUMP_API_CALL

    (void)inputLen;
    unsigned char objkey[MD5_DIGEST_LENGTH];
    unsigned keylen;
    this->CreateObjKey(objkey, keylen, objref);
    return unique_ptr<InputStream>(new PdfRC4InputStream(inputStream, inputLen, m_rc4key, m_rc4last, objkey, keylen));
}

std::unique_ptr<OutputStream> PoDoFo::PdfEncryptRC4::CreateEncryptionOutputStream(OutputStream &outputStream, const PdfReference &objref)
{
    DUMP_API_CALL
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

size_t PoDoFo::PdfEncryptRC4::CalculateStreamOffset() const
{
    DUMP_API_CALL
    return 0;
}

size_t PoDoFo::PdfEncryptRC4::CalculateStreamLength(size_t length) const
{
    DUMP_API_CALL
    return length;
}

void PoDoFo::PdfEncryptRC4::GenerateEncryptionKey(const std::string_view &documentId)
{
    DUMP_API_CALL

    unsigned char userpswd[32];
    unsigned char ownerpswd[32];

    // Pad passwords
    PadPassword(m_userPass, userpswd);
    PadPassword(m_ownerPass, ownerpswd);

    // Compute O value
    ComputeOwnerKey(userpswd, ownerpswd, m_keyLength, m_rValue, false, m_oValue);

    // Compute encryption key and U value
    m_documentId = documentId;
    ComputeEncryptionKey(m_documentId, userpswd,
        m_oValue, m_pValue, m_eKeyLength, m_rValue, m_uValue, m_EncryptMetadata);
}

bool PoDoFo::PdfEncryptRC4::Authenticate(const std::string_view &password, const std::string_view &documentId)
{
    DUMP_API_CALL

    bool success = false;

    m_documentId = documentId;

    // Pad password
    unsigned char userKey[32];
    unsigned char pswd[32];
    PadPassword(password, pswd);

    // Check password: 1) as user password, 2) as owner password
    ComputeEncryptionKey(m_documentId, pswd, m_oValue, m_pValue, m_eKeyLength, m_rValue, userKey, m_EncryptMetadata);

    success = CheckKey(userKey, m_uValue);
    if (!success)
    {
        unsigned char userpswd[32];
        ComputeOwnerKey(m_oValue, pswd, m_keyLength, m_rValue, true, userpswd);
        ComputeEncryptionKey(m_documentId, userpswd, m_oValue, m_pValue, m_eKeyLength, m_rValue, userKey, m_EncryptMetadata);
        success = CheckKey(userKey, m_uValue);
        if (success)
            m_ownerPass = password;
    }
    else
        m_userPass = password;

    return success;
}

#pragma GCC diagnostic pop