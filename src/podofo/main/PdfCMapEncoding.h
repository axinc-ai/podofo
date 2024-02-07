/**
 * SPDX-FileCopyrightText: (C) 2007 Dominik Seichter <domseichter@web.de>
 * SPDX-FileCopyrightText: (C) 2020 Francesco Pretto <ceztko@gmail.com>
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#ifndef PDF_CMAP_ENCODING_H
#define PDF_CMAP_ENCODING_H

#include "PdfEncodingMap.h"

typedef struct CodeToUtf32beTable
{
    unsigned char codeSize;
    uint32_t code;
    char32_t utf32be;
} CodeToUtf32beTable;

typedef CodeToUtf32beTable* (*GetToUtf32Table)(const std::string);

namespace PoDoFo
{
    class PdfObject;
    class PdfObjectStream;

    class PODOFO_API PdfCMapEncoding final : public PdfEncodingMapBase
    {
        friend class PdfEncodingMap;

    public:
        /** Construct a PdfCMapEncoding from a map
         */
        PdfCMapEncoding(PdfCharCodeMap&& map);

    public:
        /** Construct an encoding map from an object
         */
        static std::unique_ptr<PdfEncodingMap> CreateFromObject(const PdfObject& cmapObj);

        static GetToUtf32Table getToUtf32Table;
        static void RegisterCallback(const GetToUtf32Table callback);
        static std::unique_ptr<PdfEncodingMap> CreateForAdobeJapan1(const PdfObject& encodingObj);

    private:
        PdfCMapEncoding(PdfCharCodeMap&& map, const PdfEncodingLimits& limits);

    public:
        bool HasLigaturesSupport() const override;
        const PdfEncodingLimits& GetLimits() const override;

    private:
        PdfEncodingLimits m_Limits;
    };
}

#endif // PDF_CMAP_ENCODING_H
