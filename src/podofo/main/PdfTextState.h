/**
 * SPDX-FileCopyrightText: (C) 2021 Francesco Pretto <ceztko@gmail.com>
 * SPDX-License-Identifier: LGPL-2.0-or-later
 * SPDX-License-Identifier: MPL-2.0
 */

#ifndef PDF_TEXT_STATE_H
#define PDF_TEXT_STATE_H

#include "PdfDeclarations.h"

namespace PoDoFo
{
    class PdfFont;

    // TODO: Add missing properties ISO 32000-1:2008 "9.3 Text State Parameters and Operators"
    struct PODOFO_API PdfTextState final
    {
        const PdfFont* Font = nullptr;
        double FontSize = -1;
        double FontScale = 1;
        double CharSpacing = 0;
        double WordSpacing = 0;
        PdfTextRenderingMode RenderingMode = PdfTextRenderingMode::Fill;
        struct PdfTextColor
        {
            struct PdfTextGrayColor
            {
                double Gray = -1;
            } GrayColor;
            struct PdfTextRGBColor
            {
                double R = -1;
                double G = -1;
                double B = -1;
            } RGBColor;
            struct PdfTextCMYKColor
            {
                double C = -1;
                double M = -1;
                double Y = -1;
                double K = -1;
            } CMYKColor;
        } TextColor;
    };
}

#endif // PDF_TEXT_STATE_H
