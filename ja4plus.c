/* ja4plus.c  -- ja4+ implementation
 *
 * Copyright 2023 AOL Inc. All rights reserved.
 * Portions Copyright 2023 FoxIO
 *
 * SPDX-License-Identifier: FoxIO License 1.1
 *
 * This software requires a license to use. See
 * https://github.com/FoxIO-LLC/ja4#licensing
 * https://github.com/FoxIO-LLC/ja4/blob/main/License%20FAQ.md
 */

#include "arkime.h"
#include "../parsers/ssh_info.h"
#include <math.h>

extern ArkimeConfig_t        config;
LOCAL int                    ja4sField;
LOCAL int                    ja4sRawField;
LOCAL int                    ja4sshField;
LOCAL int                    ja4lField;
LOCAL int                    ja4lDeltaField;
LOCAL int                    ja4lsField;
LOCAL int                    ja4lsDeltaField;
LOCAL int                    ja4tField;
LOCAL int                    ja4tsField;
LOCAL int                    ja4hField;
LOCAL int                    ja4hRawField;
LOCAL int                    ja4dField;
LOCAL int                    ja4d6Field;
LOCAL int                    ja4nField;


LOCAL int                    ja4plus_plugin_num;
LOCAL GChecksum             *checksums256[ARKIME_MAX_PACKET_THREADS];
extern uint8_t               arkime_char_to_hexstr[256][3];
LOCAL gboolean               ja4Raw;
LOCAL gboolean               ja4hOmitZeroSections;
LOCAL gboolean               ja4nEnable;

#define JA4PLUS_SYN_ACK_COUNT 4
typedef struct {
    // Used for JA4L
    // Timestamps are reference against firstPacket
    uint32_t       timestampA;
    //timestampB = synAckTimes[synAckTimesCnt - 1]
    uint32_t       timestampC;
    uint32_t       timestampD;
    uint32_t       timestampE;

    uint32_t       synAckTimes[JA4PLUS_SYN_ACK_COUNT];

    // Everything in the ja4ts before the timing section, only allocated once a
    // retransmitted syn-ack creates that section, so a later rst can re-emit
    // without still having the syn-ack header around
    char          *ja4tsPrefix;

    uint8_t        client_ttl;
    uint8_t        server_ttl;
    uint8_t        synAckTimesCnt: 3;
} JA4PlusTCP_t;

typedef struct {
    GString       *header_value;   // current header value
    GString       *header_fields;
    uint16_t       cookies;
    uint16_t       referer;
    uint16_t       headers;
    char           state;
    gchar         *sorted_cookie_fields;
    gchar         *sorted_cookie_values;
    gchar          accept_lang[4];
} JA4PlusHTTP_t;

#define JA4PLUS_TCP_DONE GINT_TO_POINTER(1)
typedef struct {
    JA4PlusTCP_t  *tcp;
    JA4PlusHTTP_t *http;
} JA4PlusData_t;

typedef struct {
    char      *field;
    const char *value;
    uint16_t   flen;
    uint16_t   vlen;
} JA4PlusCookie_t;

#define TIMESTAMP_TO_RUSEC(ts) (ts.tv_sec - session->firstPacket.tv_sec) * 1000000 + (ts.tv_usec - session->firstPacket.tv_usec)

/******************************************************************************/
LOCAL int cookie_cmp(const void *a, const void *b)
{
    const JA4PlusCookie_t *ca = (JA4PlusCookie_t *)a;
    const JA4PlusCookie_t *cb = (JA4PlusCookie_t *)b;
    int rc = strcmp(ca->field, cb->field);
    if (rc != 0)
        return rc;

    // Tiebreaker: sort by value when cookie names are equal
    int minlen = ca->vlen < cb->vlen ? ca->vlen : cb->vlen;
    rc = memcmp(ca->value ? ca->value : "", cb->value ? cb->value : "", minlen);
    if (rc != 0)
        return rc;
    return ca->vlen - cb->vlen;
}

/******************************************************************************/
/* Actually process the cookie/accept-language header that has been saved up. */
LOCAL void ja4plus_http_process_headers (ArkimeSession_t *session)
{
    JA4PlusData_t *ja4plus_data = (JA4PlusData_t *) session->pluginData[ja4plus_plugin_num];
    JA4PlusHTTP_t *ja4_http = ja4plus_data->http;

    if (ja4_http->state == 'c') {
        int num = 0;
        JA4PlusCookie_t cookies[100];
        const char *start = ja4_http->header_value->str;
        const char *end = start + ja4_http->header_value->len;

        uint32_t totalFlen = 0;
        uint32_t totalVlen = 0;
        while (start < end) {
            while (start < end && isspace(*start)) start++;
            const char *equal = memchr(start, '=', end - start);
            if (!equal)
                break;
            uint32_t flen = equal - start;
            cookies[num].field = g_strndup(start, flen); // COPY
            cookies[num].flen = flen;
            totalFlen += flen;

            start = memchr(equal + 1, ';', end - (equal + 1));
            equal++;
            while (equal < end && isspace(*equal)) equal++;
            if (equal < end && equal != start) {
                int vlen = start ? start - equal : end - equal;
                cookies[num].vlen = vlen;
                totalVlen += vlen;

                cookies[num].value = equal; // NO COPY
            } else {
                cookies[num].value = 0;
                cookies[num].vlen = 0;
            }
            num++;
            if (num == 99)
                break;

            if (!start)
                break;
            start++;
        }

        ja4_http->cookies = num;

        if (num > 0) {

            qsort(cookies, num, sizeof(JA4PlusCookie_t), cookie_cmp);

            g_free(ja4_http->sorted_cookie_fields);
            ja4_http->sorted_cookie_fields = g_malloc(totalFlen + num);

            g_free(ja4_http->sorted_cookie_values);
            ja4_http->sorted_cookie_values = g_malloc(totalFlen + num + totalVlen + num);

            char *fpos = ja4_http->sorted_cookie_fields;
            char *fvpos = ja4_http->sorted_cookie_values;
            for (int i = 0; i < num; i++) {
                memcpy(fpos, cookies[i].field, cookies[i].flen);
                fpos += cookies[i].flen;
                *(fpos++) = ',';

                memcpy(fvpos, cookies[i].field, cookies[i].flen);
                fvpos += cookies[i].flen;
                *(fvpos++) = '=';

                if (cookies[i].value) {
                    memcpy(fvpos, cookies[i].value, cookies[i].vlen);
                    fvpos += cookies[i].vlen;
                }
                *(fvpos++) = ',';
            }
            *(fpos - 1) = 0;
            *(fvpos - 1) = 0;

            for (int i = 0; i < num; i++) {
                g_free(cookies[i].field);
            }
        }
    } else if (ja4_http->state == 'a') {
        const char *lang = ja4_http->header_value->str;
        size_t l = 0, a = 0;;
        while (l < ja4_http->header_value->len && a < 4) {
            if (isspace(lang[l]) || lang[l] == '-') {
                l++;
                continue;
            } else if (lang[l] == ',' || lang[l] == ';') {
                break;
            }
            ja4_http->accept_lang[a] = tolower(lang[l]);
            a++;
            l++;
        }
    }

    ja4_http->state = 0;
    g_string_truncate(ja4_http->header_value, 0);
}
/******************************************************************************/
/* An http msg is complete, process the headers and create the ja4h */
LOCAL void ja4plus_http_complete(ArkimeSession_t *session, http_parser *parser)
{
    if (parser->type != 0)
        return;

    JA4PlusData_t *ja4plus_data = (JA4PlusData_t *) session->pluginData[ja4plus_plugin_num];
    if (!ja4plus_data)
        return;

    JA4PlusHTTP_t *ja4_http = ja4plus_data->http;
    if (!ja4_http)
        return;

    char ja4h[52];

    if (!ja4_http->header_fields)
        return;

    if (ja4_http->state != 0) {
        ja4plus_http_process_headers(session);
    }

    // JA4H method code: first two characters of the method lowercased,
    // matching the FoxIO reference implementations
    char method[3] = "00";
    const char *methodStr = http_method_str(parser->method);
    if (methodStr && methodStr[0] != '<' && methodStr[0] && methodStr[1]) {
        method[0] = tolower(methodStr[0]);
        method[1] = tolower(methodStr[1]);
    }
    GChecksum *const checksum = checksums256[session->thread];
    snprintf(ja4h, sizeof(ja4h), "%s%d%d%c%c%02d%4.4s_",
             method,
             parser->http_major,
             parser->http_minor,
             (ja4_http->cookies == 0) ? 'n' : 'c',
             (ja4_http->referer == 0) ? 'n' : 'r',
             MIN(ja4_http->headers, 99),
             ja4_http->accept_lang
            );

    g_checksum_update(checksum, (guchar *)ja4_http->header_fields->str, ja4_http->header_fields->len);
    memcpy(ja4h + 13, g_checksum_get_string(checksum), 12);
    g_checksum_reset(checksum);
    ja4h[25] = '_';

    if (ja4_http->cookies) {
        g_checksum_update(checksum, (guchar *) ja4_http->sorted_cookie_fields, strlen(ja4_http->sorted_cookie_fields));
        memcpy(ja4h + 26, g_checksum_get_string(checksum), 12);
        g_checksum_reset(checksum);
        ja4h[38] = '_';

        g_checksum_update(checksum, (guchar *) ja4_http->sorted_cookie_values, strlen(ja4_http->sorted_cookie_values));
        memcpy(ja4h + 39, g_checksum_get_string(checksum), 12);
        g_checksum_reset(checksum);
        arkime_field_string_add(ja4hField, session, ja4h, 51, TRUE);
    } else if (ja4hOmitZeroSections) {
        g_strlcpy(ja4h + 26, "_", sizeof(ja4h) - 26);
        arkime_field_string_add(ja4hField, session, ja4h, 27, TRUE);
    } else {
        g_strlcpy(ja4h + 26, "000000000000_000000000000", sizeof(ja4h) - 26);
        arkime_field_string_add(ja4hField, session, ja4h, 51, TRUE);
    }

    if (ja4Raw) {
        char ja4h_r[1024];

        snprintf(ja4h_r, sizeof(ja4h_r), "%s%d%d%c%c%02d%4.4s_%s_%s_%s",
                 method,
                 parser->http_major,
                 parser->http_minor,
                 (ja4_http->cookies == 0) ? 'n' : 'c',
                 (ja4_http->referer == 0) ? 'n' : 'r',
                 MIN(ja4_http->headers, 99),
                 ja4_http->accept_lang,
                 ja4_http->header_fields->str,
                 (ja4_http->sorted_cookie_fields != NULL) ? ja4_http->sorted_cookie_fields : "",
                 (ja4_http->sorted_cookie_values != NULL) ? ja4_http->sorted_cookie_values : ""
                );
        ja4h_r[sizeof(ja4h_r) - 1] = 0;
        arkime_field_string_add(ja4hRawField, session, ja4h_r, -1, TRUE);
    }
    g_string_truncate(ja4_http->header_fields, 0);

    g_free(ja4_http->sorted_cookie_fields);
    ja4_http->sorted_cookie_fields = 0;

    g_free(ja4_http->sorted_cookie_values);
    ja4_http->sorted_cookie_values = 0;

    // Reset
    ja4_http->state = 0;
    memcpy(ja4_http->accept_lang, "0000", 4);
    ja4_http->cookies = 0;
    ja4_http->referer = 0;
    ja4_http->headers = 0;
}
/******************************************************************************/
LOCAL void ja4plus_http_header_field_raw (ArkimeSession_t *session, http_parser *hp, const char *at, size_t length)
{
    if (!at || hp->type != 0)
        return;

    JA4PlusData_t *ja4plus_data = (JA4PlusData_t *) session->pluginData[ja4plus_plugin_num];
    if (!ja4plus_data) {
        ja4plus_data = session->pluginData[ja4plus_plugin_num] = ARKIME_TYPE_ALLOC0 (JA4PlusData_t);
    }

    JA4PlusHTTP_t *ja4_http = ja4plus_data->http;
    if (!ja4plus_data->http) {
        ja4_http = ja4plus_data->http = ARKIME_TYPE_ALLOC0 (JA4PlusHTTP_t);
        ja4_http->header_value = g_string_sized_new(100);
        ja4_http->header_fields = g_string_sized_new(100);
        memcpy(ja4_http->accept_lang, "0000", 4);
    }

    if (ja4_http->state != 0) {
        ja4plus_http_process_headers(session);
    }

    char *header_field = g_ascii_strdown(at, length);
    if (strcmp(header_field, "cookie") == 0) {
        ja4_http->state = 'c';
    } else if (strcmp(header_field, "referer") == 0) {
        ja4_http->referer = 1;
    } else {
        if (ja4_http->headers > 0) {
            g_string_append_len(ja4_http->header_fields, ",", 1);
        }
        g_string_append_len(ja4_http->header_fields, at, length);
        ja4_http->headers++;
        if (strcmp(header_field, "accept-language") == 0) {
            ja4_http->state = 'a';
        } else {
            ja4_http->state = 0;
        }
    }
    g_free(header_field);
}
/******************************************************************************/
/* New partial value is coming in, append it to the current value if we are in a cookie/accept-language */
LOCAL void ja4plus_http_header_value (ArkimeSession_t *session, http_parser *hp, const char *at, size_t length)
{
    if (!at || hp->type != 0)
        return;

    JA4PlusData_t *ja4plus_data = (JA4PlusData_t *) session->pluginData[ja4plus_plugin_num];
    JA4PlusHTTP_t *ja4_http = ja4plus_data->http;

    if (ja4_http->state == 0)
        return;

    g_string_append_len(ja4_http->header_value, at, length);
}
/******************************************************************************/
// https://tools.ietf.org/html/draft-davidben-tls-grease-00
LOCAL int ja4plus_is_grease_value(uint32_t val)
{
    if ((val & 0x0f) != 0x0a)
        return 0;

    if ((val & 0xff) != ((val >> 8) & 0xff))
        return 0;

    return 1;
}
/******************************************************************************/
LOCAL void ja4plus_ja4_version(uint16_t ver, char dtls, char vstr[3])
{
    switch (ver) {
    case 0x0002:
        memcpy(vstr, "s2", 3);
        break;
    case 0x0300:
        memcpy(vstr, "s3", 3);
        break;
    case 0x0301:
        memcpy(vstr, "10", 3);
        break;
    case 0x0302:
        memcpy(vstr, "11", 3);
        break;
    case 0x0303:
        memcpy(vstr, "12", 3);
        break;
    case 0x0304:
        memcpy(vstr, "13", 3);
        break;
    case 0xfeff:
        if (dtls)
            memcpy(vstr, "d1", 3);
        else
            memcpy(vstr, "00", 3);
        break;
    case 0xfefd:
        if (dtls)
            memcpy(vstr, "d2", 3);
        else
            memcpy(vstr, "00", 3);
        break;
    case 0xfefc:
        if (dtls)
            memcpy(vstr, "d3", 3);
        else
            memcpy(vstr, "00", 3);
        break;
    default:
        memcpy(vstr, "00", 3);
        break;
    }
}
/******************************************************************************/
LOCAL void ja4plus_2digit_to_string(int val, char *str)
{
    if (val >= 99) {
        str[0] = '9';
        str[1] = '9';
        return;
    }
    str[0] = (val / 10) + '0';
    str[1] = (val % 10) + '0';
}

/******************************************************************************/
LOCAL void ja4plus_alpn_to_ja4alpn(const uint8_t *alpn, int len, uint8_t *ja4alpn)
{
    if (len == 0)
        return;

    len--;  // len now the offset of last byte, which could be 0
    if (isalnum(alpn[0]) && isalnum(alpn[len])) {
        ja4alpn[0] = alpn[0];
        ja4alpn[1] = alpn[len];
    } else {
        ja4alpn[0] = arkime_char_to_hexstr[alpn[0]][0];
        ja4alpn[1] = arkime_char_to_hexstr[alpn[len]][1];
    }
}

/******************************************************************************/
LOCAL uint32_t ja4plus_dtls_process_server_hello(ArkimeSession_t *session, const uint8_t *data, int len, void UNUSED(*uw))
{
    // https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4S.md
    int      ja4NumExtensions = 0;
    uint16_t ja4Extensions[256];
    uint8_t  ja4ALPN[2] = {'0', '0'};
    BSB      bsb;

    BSB_INIT(bsb, data, len);

    uint16_t ver = 0;
    uint16_t supportedver;
    BSB_IMPORT_u16(bsb, ver);
    supportedver = ver;
    BSB_IMPORT_skip(bsb, 32);     // Random

    if (BSB_IS_ERROR(bsb))
        return -1;

    int skiplen = 0;
    BSB_IMPORT_u08(bsb, skiplen);   // Session Id Length
    BSB_IMPORT_skip(bsb, skiplen);  // Session Id

    uint16_t cipher = 0;
    BSB_IMPORT_u16(bsb, cipher);
    char cipherHex[5];
    snprintf(cipherHex, sizeof(cipherHex), "%04x", cipher);


    BSB_IMPORT_skip(bsb, 1);

    if (BSB_REMAINING(bsb) > 2) {
        int etotlen = 0;
        BSB_IMPORT_u16(bsb, etotlen);  // Extensions Length

        etotlen = MIN(etotlen, BSB_REMAINING(bsb));

        BSB ebsb;
        BSB_INIT(ebsb, BSB_WORK_PTR(bsb), etotlen);

        while (BSB_REMAINING(ebsb) > 0) {
            int etype = 0, elen = 0;

            BSB_IMPORT_u16 (ebsb, etype);
            BSB_IMPORT_u16 (ebsb, elen);

            // A truncated header
            if (BSB_IS_ERROR(ebsb))
                break;

            if (ja4plus_is_grease_value(etype)) {
                BSB_IMPORT_skip (ebsb, elen);
                continue;
            }

            if (ja4NumExtensions < ARRAY_LEN(ja4Extensions))
                ja4Extensions[ja4NumExtensions++] = etype;

            if (elen > BSB_REMAINING(ebsb))
                break;

            if (etype == 0x2b && elen == 2) { // etype 0x2b is supported version
                uint16_t sv = 0;
                BSB_IMPORT_u16(ebsb, sv);

                // The extension replaces the header version per the JA4 spec;
                // MAX() would pick the wrong one for DTLS where values descend
                if (!ja4plus_is_grease_value(sv))
                    supportedver = sv;
                continue; // Already processed ebsb above
            }

            if (etype == 0x10) { // ALPN
                BSB alpnBsb;
                BSB_IMPORT_bsb (ebsb, alpnBsb, elen);

                BSB_IMPORT_skip (alpnBsb, 2); // len
                uint8_t plen = 0;
                BSB_IMPORT_u08 (alpnBsb, plen); // len
                const unsigned char *pstr = NULL;
                BSB_IMPORT_ptr (alpnBsb, pstr, plen);
                if (plen > 0 && pstr && !BSB_IS_ERROR(alpnBsb)) {
                    ja4plus_alpn_to_ja4alpn(pstr, plen, ja4ALPN);
                }
                continue; // Already processed ebsb above
            }
            BSB_IMPORT_skip (ebsb, elen);
        }
    }

    // JA4s Creation
    char vstr[3];
    ja4plus_ja4_version(supportedver, TRUE, vstr);

    char ja4s[26];
    ja4s[25] = 0;
    ja4s[0] = 'd';
    ja4s[1] = vstr[0];
    ja4s[2] = vstr[1];
    ja4plus_2digit_to_string(ja4NumExtensions, ja4s + 3);
    ja4s[5] = ja4ALPN[0];
    ja4s[6] = ja4ALPN[1];
    ja4s[7] = '_';
    memcpy(ja4s + 8, cipherHex, 4);
    ja4s[12] = '_';

    char tmpBuf[5 * 256 + 1];  // 256 "%04x," entries + snprintf NUL
    BSB tmpBSB;

    BSB_INIT(tmpBSB, tmpBuf, sizeof(tmpBuf));
    for (int i = 0; i < ja4NumExtensions; i++) {
        BSB_EXPORT_sprintf(tmpBSB, "%04x,", ja4Extensions[i]);
    }
    if (ja4NumExtensions > 0) {
        BSB_EXPORT_rewind(tmpBSB, 1); // Remove last ,
    }

    GChecksum *const checksum = checksums256[session->thread];

    if (BSB_LENGTH(tmpBSB) > 0) {
        g_checksum_update(checksum, (guchar *)tmpBuf, BSB_LENGTH(tmpBSB));
        memcpy(ja4s + 13, g_checksum_get_string(checksum), 12);
        g_checksum_reset(checksum);
    } else {
        memcpy(ja4s + 13, "000000000000", 12);
    }

    arkime_field_string_add(ja4sField, session, ja4s, 25, TRUE);

    if (ja4Raw) {
        char ja4s_r[13 + 5 * 256];
        memcpy(ja4s_r, ja4s, 13);
        memcpy(ja4s_r + 13, tmpBuf, BSB_LENGTH(tmpBSB));

        arkime_field_string_add(ja4sRawField, session, ja4s_r, 13 + BSB_LENGTH(tmpBSB), TRUE);
    }

    return 0;
}
/******************************************************************************/
LOCAL uint32_t ja4plus_tls_process_server_hello(ArkimeSession_t *session, const uint8_t *data, int len, void UNUSED(*uw))
{
    // https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4S.md
    int      ja4NumExtensions = 0;
    uint16_t ja4Extensions[256];
    uint8_t  ja4ALPN[2] = {'0', '0'};
    BSB      bsb;

    BSB_INIT(bsb, data, len);

    uint16_t ver = 0;
    uint16_t supportedver;
    BSB_IMPORT_u16(bsb, ver);
    supportedver = ver;
    BSB_IMPORT_skip(bsb, 32);     // Random

    if (BSB_IS_ERROR(bsb))
        return -1;

    /* Parse sessionid, only for SSLv3 - TLSv1.2 */
    if (ver >= 0x0300 && ver <= 0x0303) {
        int skiplen = 0;
        BSB_IMPORT_u08(bsb, skiplen);   // Session Id Length
        BSB_IMPORT_skip(bsb, skiplen);  // Session Id
    }

    uint16_t cipher = 0;
    BSB_IMPORT_u16(bsb, cipher);
    char cipherHex[5];
    snprintf(cipherHex, sizeof(cipherHex), "%04x", cipher);


    /* Thanks wireshark - No compression with TLS 1.3 before draft -22 */
    if (ver < 0x0700 || ver >= 0x7f16) {
        BSB_IMPORT_skip(bsb, 1);
    }

    if (BSB_REMAINING(bsb) > 2) {
        int etotlen = 0;
        BSB_IMPORT_u16(bsb, etotlen);  // Extensions Length

        etotlen = MIN(etotlen, BSB_REMAINING(bsb));

        BSB ebsb;
        BSB_INIT(ebsb, BSB_WORK_PTR(bsb), etotlen);

        while (BSB_REMAINING(ebsb) > 0) {
            int etype = 0, elen = 0;

            BSB_IMPORT_u16 (ebsb, etype);
            BSB_IMPORT_u16 (ebsb, elen);

            // A truncated header
            if (BSB_IS_ERROR(ebsb))
                break;

            if (ja4plus_is_grease_value(etype)) {
                BSB_IMPORT_skip (ebsb, elen);
                continue;
            }

            if (ja4NumExtensions < ARRAY_LEN(ja4Extensions))
                ja4Extensions[ja4NumExtensions++] = etype;

            if (elen > BSB_REMAINING(ebsb))
                break;

            if (etype == 0x2b && elen == 2) { // etype 0x2b is supported version
                uint16_t sv = 0;
                BSB_IMPORT_u16(ebsb, sv);

                // The extension replaces the header version per the JA4 spec;
                // MAX() would pick the wrong one for DTLS where values descend
                if (!ja4plus_is_grease_value(sv))
                    supportedver = sv;
                continue; // Already processed ebsb above
            }

            if (etype == 0x10) { // ALPN
                BSB alpnBsb;
                BSB_IMPORT_bsb (ebsb, alpnBsb, elen);

                BSB_IMPORT_skip (alpnBsb, 2); // len
                uint8_t plen = 0;
                BSB_IMPORT_u08 (alpnBsb, plen); // len
                const unsigned char *pstr = NULL;
                BSB_IMPORT_ptr (alpnBsb, pstr, plen);
                if (plen > 0 && pstr && !BSB_IS_ERROR(alpnBsb)) {
                    ja4plus_alpn_to_ja4alpn(pstr, plen, ja4ALPN);
                }
                continue; // Already processed ebsb above
            }
            BSB_IMPORT_skip (ebsb, elen);
        }
    }

    // JA4s Creation
    char vstr[3];
    ja4plus_ja4_version(supportedver, FALSE, vstr);

    char ja4s[26];
    ja4s[25] = 0;
    ja4s[0] = (session->ipProtocol == IPPROTO_TCP) ? 't' : 'q';
    ja4s[1] = vstr[0];
    ja4s[2] = vstr[1];
    ja4plus_2digit_to_string(ja4NumExtensions, ja4s + 3);
    ja4s[5] = ja4ALPN[0];
    ja4s[6] = ja4ALPN[1];
    ja4s[7] = '_';
    memcpy(ja4s + 8, cipherHex, 4);
    ja4s[12] = '_';

    char tmpBuf[5 * 256 + 1];  // 256 "%04x," entries + snprintf NUL
    BSB tmpBSB;

    BSB_INIT(tmpBSB, tmpBuf, sizeof(tmpBuf));
    for (int i = 0; i < ja4NumExtensions; i++) {
        BSB_EXPORT_sprintf(tmpBSB, "%04x,", ja4Extensions[i]);
    }
    if (ja4NumExtensions > 0) {
        BSB_EXPORT_rewind(tmpBSB, 1); // Remove last ,
    }

    GChecksum *const checksum = checksums256[session->thread];

    if (BSB_LENGTH(tmpBSB) > 0) {
        g_checksum_update(checksum, (guchar *)tmpBuf, BSB_LENGTH(tmpBSB));
        memcpy(ja4s + 13, g_checksum_get_string(checksum), 12);
        g_checksum_reset(checksum);
    } else {
        memcpy(ja4s + 13, "000000000000", 12);
    }

    arkime_field_string_add(ja4sField, session, ja4s, 25, TRUE);

    if (ja4Raw) {
        char ja4s_r[13 + 5 * 256];
        memcpy(ja4s_r, ja4s, 13);
        memcpy(ja4s_r + 13, tmpBuf, BSB_LENGTH(tmpBSB));

        arkime_field_string_add(ja4sRawField, session, ja4s_r, 13 + BSB_LENGTH(tmpBSB), TRUE);
    }

    return 0;
}
/******************************************************************************/
LOCAL void ja4plus_cert_process_rdn(BSB *bsb, BSB *out)
{
    uint32_t apc, atag, alen;

    while (BSB_REMAINING(*bsb) > 3) {
        uint8_t *value = arkime_parsers_asn_get_tlv(bsb, &apc, &atag, &alen);

        if (!value)
            return;

        if (apc) {
            BSB tbsb;
            BSB_INIT(tbsb, value, alen);
            ja4plus_cert_process_rdn(&tbsb, out);
        } else if (atag == 6 && alen >= 3) {
            for (uint32_t i = 0; i < alen; i++) {
                BSB_EXPORT_ptr(*out, arkime_char_to_hexstr[value[i]], 2);
            }
            BSB_EXPORT_u08(*out, ',');
            return;
        }
    }
}
/******************************************************************************/
LOCAL void ja4plus_cert_print(int thread, int pos, char *ja4x, BSB *out)
{
    GChecksum *const checksum = checksums256[thread];

    if (BSB_LENGTH(*out) > 0) {
        BSB_EXPORT_rewind(*out, 1);
        g_checksum_update(checksum, (guchar *)out->buf, BSB_LENGTH(*out));
        memcpy(ja4x + (13 * pos), g_checksum_get_string(checksum), 12);
        g_checksum_reset(checksum);
    } else {
        memcpy(ja4x + (13 * pos), "000000000000", 12);
    }
}
/******************************************************************************/
LOCAL uint32_t ja4plus_process_certificate_wInfo(ArkimeSession_t *session, const uint8_t *data, int len, void *uw)
{
    // https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4X.md

    uint32_t atag, alen, apc;
    uint8_t *value;

    BSB      bsb;
    BSB_INIT(bsb, data, len);

    /* Certificate */
    if (!(value = arkime_parsers_asn_get_tlv(&bsb, &apc, &atag, &alen))) {
        goto bad_cert;
    }
    BSB_INIT(bsb, value, alen);

    /* signedCertificate */
    if (!(value = arkime_parsers_asn_get_tlv(&bsb, &apc, &atag, &alen))) {
        goto bad_cert;
    }
    BSB_INIT(bsb, value, alen);

    /* serialNumber or version*/
    if (!(value = arkime_parsers_asn_get_tlv(&bsb, &apc, &atag, &alen))) {
        goto bad_cert;
    }

    if (apc) {
        if (!(value = arkime_parsers_asn_get_tlv(&bsb, &apc, &atag, &alen))) {
            goto bad_cert;
        }
    }

    /* signature */
    if (!arkime_parsers_asn_get_tlv(&bsb, &apc, &atag, &alen)) {
        goto bad_cert;
    }

    /* issuer */
    if (!(value = arkime_parsers_asn_get_tlv(&bsb, &apc, &atag, &alen))) {
        goto bad_cert;
    }
    BSB out;
    char outbuf[1000];
    char ja4x[39];
    char ja4x_r[3100]; // 3 sections of up to ~1000 + separators
    ja4x[12] = ja4x[25] = '_';
    ja4x[38] = 0;

    BSB ja4x_rbsb;
    BSB_INIT(ja4x_rbsb, ja4x_r, sizeof(ja4x_r));

    BSB tbsb;
    BSB_INIT(tbsb, value, alen);

    BSB_INIT(out, outbuf, sizeof(outbuf));
    ja4plus_cert_process_rdn(&tbsb, &out);
    if (BSB_LENGTH(out) > 0)
        BSB_EXPORT_ptr(ja4x_rbsb, out.buf, BSB_LENGTH(out) - 1);
    BSB_EXPORT_u08(ja4x_rbsb, '_');

    ja4plus_cert_print(session->thread, 0,  ja4x, &out);

    /* validity */
    if (!(value = arkime_parsers_asn_get_tlv(&bsb, &apc, &atag, &alen))) {
        goto bad_cert;
    }

    BSB_INIT(tbsb, value, alen);
    if (!(value = arkime_parsers_asn_get_tlv(&tbsb, &apc, &atag, &alen))) {
        goto bad_cert;
    }

    if (!(value = arkime_parsers_asn_get_tlv(&tbsb, &apc, &atag, &alen))) {
        goto bad_cert;
    }

    /* subject */
    if (!(value = arkime_parsers_asn_get_tlv(&bsb, &apc, &atag, &alen))) {
        goto bad_cert;
    }
    BSB_INIT(tbsb, value, alen);

    BSB_INIT(out, outbuf, sizeof(outbuf));
    ja4plus_cert_process_rdn(&tbsb, &out);
    if (BSB_LENGTH(out) > 0)
        BSB_EXPORT_ptr(ja4x_rbsb, out.buf, BSB_LENGTH(out) - 1);
    BSB_EXPORT_u08(ja4x_rbsb, '_');

    ja4plus_cert_print(session->thread, 1, ja4x, &out);

    /* subjectPublicKeyInfo */
    if (!(value = arkime_parsers_asn_get_tlv(&bsb, &apc, &atag, &alen))) {
        goto bad_cert;
    }

    /* extensions */
    BSB_INIT(out, outbuf, sizeof(outbuf));
    ja4plus_cert_process_rdn(&bsb, &out);
    if (BSB_LENGTH(out) > 0)
        BSB_EXPORT_ptr(ja4x_rbsb, out.buf, BSB_LENGTH(out) - 1);
    BSB_EXPORT_u08(ja4x_rbsb, 0);

    ja4plus_cert_print(session->thread, 2, ja4x, &out);

    arkime_field_certsinfo_update_extra(uw, g_strdup("ja4x"), g_strdup(ja4x));
    if (ja4Raw && BSB_NOT_ERROR(ja4x_rbsb)) {
        arkime_field_certsinfo_update_extra(uw, g_strdup("ja4x_r"), g_strdup(ja4x_r));
    }
    return 0;

bad_cert:
    return 0;
}
/******************************************************************************/
// Given a list of numbers find the mode, we ignore numbers > 2048
LOCAL int ja4plus_ssh_mode(const uint16_t *nums, int num)
{
    unsigned char  count[2048];
    unsigned short mode = 0;
    unsigned char  modeCount = 0;
    memset(count, 0, sizeof(count));
    for (int i = 0; i < num; i++) {
        if (nums[i] >= 2048)
            continue;
        count[nums[i]]++;
        if (count[nums[i]] == modeCount && nums[i] < mode) {
            // new count same as old max, but lower mode
            mode = nums[i];
        } else if (count[nums[i]] > modeCount) {
            mode = nums[i];
            modeCount = count[nums[i]];
        }

    }
    return mode;
}
/******************************************************************************/
LOCAL uint32_t ja4plus_ssh_ja4ssh(ArkimeSession_t *session, const uint8_t *UNUSED(data), int UNUSED(len), void *uw)
{
    // https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4SSH.md
    char ja4ssh[50];
    BSB bsb;

    const SSHInfo_t *ssh = uw;

    BSB_INIT(bsb, ja4ssh, sizeof(ja4ssh));
    BSB_EXPORT_sprintf(bsb, "c%ds%d_c%ds%d_c%ds%d",
                       ja4plus_ssh_mode(ssh->lens[0], ssh->packets200[0]), ja4plus_ssh_mode(ssh->lens[1], ssh->packets200[1]),
                       ssh->packets200[0], ssh->packets200[1],
                       session->tcpFlagAckCnt[0], session->tcpFlagAckCnt[1]);
    session->tcpFlagAckCnt[0] = session->tcpFlagAckCnt[1] = 0;

    arkime_field_string_add(ja4sshField, session, ja4ssh, BSB_LENGTH(bsb), TRUE);
    return 0;
}
/******************************************************************************/
LOCAL void ja4plus_ja4ts_times(BSB *obsb, const JA4PlusTCP_t *data)
{
    for (int i = 1; i < data->synAckTimesCnt; i++) {
        BSB_EXPORT_sprintf(*obsb, "%.0f-", round ((data->synAckTimes[i] - data->synAckTimes[i - 1]) / 1000000.0));
    }
    BSB_EXPORT_rewind(*obsb, 1); // remove last -
}
/******************************************************************************/
LOCAL void ja4plus_ja4ts(ArkimeSession_t *session, JA4PlusTCP_t *data, const struct tcphdr *tcph)
{
    uint8_t        *p = (uint8_t *)tcph + 20;
    const uint8_t  *end = (uint8_t *)tcph + tcph->th_off * 4;
    // Both references default these to 0 and render 0 as "00", so an absent
    // option and a zero value are deliberately indistinguishable. A sentinel
    // would collide with a real mss of 65535.
    uint16_t        mss = 0;
    uint8_t         window_scale = 0;

    char obuf[100];
    BSB obsb;

    BSB_INIT(obsb, obuf, sizeof(obuf));
    BSB_EXPORT_sprintf(obsb, "%d_", ntohs(tcph->th_win));
    if (p == end) {
        BSB_EXPORT_cstr(obsb, "00");
    } else {
        BSB hbsb;
        BSB_INIT(hbsb, p, (int)(end - p));

        while (BSB_REMAINING(hbsb) > 0 && !BSB_IS_ERROR(hbsb)) {
            uint8_t next = 0;
            BSB_IMPORT_u08(hbsb, next);
            BSB_EXPORT_sprintf(obsb, "%d-", next);
            if (next == 0) { // End of list
                while (BSB_REMAINING(hbsb) > 0) { // Just keep adding all 0s after
                    BSB_IMPORT_u08(hbsb, next);
                    if (next == 0) {
                        BSB_EXPORT_sprintf(obsb, "%d-", next);
                    } else {
                        break;
                    }
                }
                break;
            }

            if (next == 1) // NOOP
                continue;

            uint8_t size = 0;
            BSB_IMPORT_u08(hbsb, size);
            if (size < 2 || BSB_REMAINING(hbsb) < size - 2)
                break;

            // Always consume the declared size, like the wireshark and zeek
            // references, so an option with a non standard length doesn't
            // desync the rest of the walk
            if (next == 2 && size >= 4) {
                BSB_IMPORT_u16(hbsb, mss);
                BSB_IMPORT_skip(hbsb, size - 4);
            } else if (next == 3 && size >= 3) {
                BSB_IMPORT_u08(hbsb, window_scale);
                BSB_IMPORT_skip(hbsb, size - 3);
            } else {
                BSB_IMPORT_skip(hbsb, size - 2);
            }
        }

        BSB_EXPORT_rewind(obsb, 1); // remove last -
    }

    BSB_EXPORT_sprintf(obsb, "_%02d", mss);

    if (window_scale == 0) {
        BSB_EXPORT_cstr(obsb, "_00");
    } else {
        BSB_EXPORT_sprintf(obsb, "_%d", window_scale);
    }

    if (data->synAckTimesCnt > 1) {
        if (!data->ja4tsPrefix && BSB_NOT_ERROR(obsb))
            data->ja4tsPrefix = g_strndup(obuf, BSB_LENGTH(obsb));

        BSB_EXPORT_cstr(obsb, "_");
        ja4plus_ja4ts_times(&obsb, data);
    }

    BSB_EXPORT_u08(obsb, 0);
    arkime_field_string_add(ja4tsField, session, obuf, -1, TRUE);
}
/******************************************************************************/
/* A rst ending the syn-ack sequence appends -R<seconds since the last syn-ack>.
 * Both references only emit it inside the timing section, so it needs 2+
 * syn-acks, which is exactly when ja4tsPrefix has been stashed.
 */
LOCAL void ja4plus_ja4ts_rst(ArkimeSession_t *session, const JA4PlusTCP_t *data, uint32_t rstTime)
{
    char obuf[100];
    BSB  obsb;

    BSB_INIT(obsb, obuf, sizeof(obuf));
    BSB_EXPORT_cstr(obsb, data->ja4tsPrefix);
    BSB_EXPORT_cstr(obsb, "_");
    ja4plus_ja4ts_times(&obsb, data);
    BSB_EXPORT_sprintf(obsb, "-R%.0f", round ((rstTime - data->synAckTimes[data->synAckTimesCnt - 1]) / 1000000.0));

    BSB_EXPORT_u08(obsb, 0);
    arkime_field_string_add(ja4tsField, session, obuf, -1, TRUE);
}
/******************************************************************************/
LOCAL void ja4plus_ja4t(ArkimeSession_t *session, JA4PlusTCP_t UNUSED(*data), const struct tcphdr *tcph)
{
    uint8_t        *p = (uint8_t *)tcph + 20;
    const uint8_t  *end = (uint8_t *)tcph + tcph->th_off * 4;
    // Both references default these to 0 and render 0 as "00", so an absent
    // option and a zero value are deliberately indistinguishable. A sentinel
    // would collide with a real mss of 65535.
    uint16_t        mss = 0;
    uint8_t         window_scale = 0;

    char obuf[100];
    BSB obsb;

    BSB_INIT(obsb, obuf, sizeof(obuf));
    BSB_EXPORT_sprintf(obsb, "%d_", ntohs(tcph->th_win));
    if (p == end) {
        BSB_EXPORT_cstr(obsb, "00");
    } else {
        BSB hbsb;
        BSB_INIT(hbsb, p, (int)(end - p));

        while (BSB_REMAINING(hbsb) > 0 && !BSB_IS_ERROR(hbsb)) {
            uint8_t next = 0;
            BSB_IMPORT_u08(hbsb, next);
            BSB_EXPORT_sprintf(obsb, "%d-", next);
            if (next == 0) { // End of list
                while (BSB_REMAINING(hbsb) > 0) { // Just keep adding all 0s after
                    BSB_IMPORT_u08(hbsb, next);
                    if (next == 0) {
                        BSB_EXPORT_sprintf(obsb, "%d-", next);
                    } else {
                        break;
                    }
                }
                break;
            }

            if (next == 1) // NOOP
                continue;

            uint8_t size = 0;
            BSB_IMPORT_u08(hbsb, size);
            if (size < 2 || BSB_REMAINING(hbsb) < size - 2)
                break;

            // Always consume the declared size, like the wireshark and zeek
            // references, so an option with a non standard length doesn't
            // desync the rest of the walk
            if (next == 2 && size >= 4) {
                BSB_IMPORT_u16(hbsb, mss);
                BSB_IMPORT_skip(hbsb, size - 4);
            } else if (next == 3 && size >= 3) {
                BSB_IMPORT_u08(hbsb, window_scale);
                BSB_IMPORT_skip(hbsb, size - 3);
            } else {
                BSB_IMPORT_skip(hbsb, size - 2);
            }
        }

        BSB_EXPORT_rewind(obsb, 1); // remove last -
    }

    BSB_EXPORT_sprintf(obsb, "_%02d", mss);

    if (window_scale == 0) {
        BSB_EXPORT_cstr(obsb, "_00");
    } else {
        BSB_EXPORT_sprintf(obsb, "_%d", window_scale);
    }

    BSB_EXPORT_u08(obsb, 0);
    arkime_field_string_add(ja4tField, session, obuf, -1, TRUE);
}
/******************************************************************************/
/* Ratio of the two latencies that make up a ja4l/ja4ls. The halving both are
 * displayed with cancels out, so the raw differences are used. The FoxIO
 * wireshark reference divides unconditionally and emits an inf, we skip the
 * field instead.
 */
LOCAL void ja4plus_ja4l_delta(ArkimeSession_t *session, int field, uint32_t num, uint32_t den)
{
    if (den == 0)
        return;

    char delta[20];
    snprintf(delta, sizeof(delta), "%.1f", (double)num / (double)den);
    arkime_field_string_add(field, session, delta, -1, TRUE);
}
/******************************************************************************/
LOCAL uint32_t ja4plus_tcp_raw_packet(ArkimeSession_t *session, const uint8_t *UNUSED(d), int UNUSED(l), void *uw)
{
    JA4PlusData_t *ja4plus_data = session->pluginData[ja4plus_plugin_num];
    JA4PlusTCP_t  *ja4plus_tcp;
    if (!ja4plus_data) {
        ja4plus_data = session->pluginData[ja4plus_plugin_num] = ARKIME_TYPE_ALLOC0 (JA4PlusData_t);
        ja4plus_tcp = ja4plus_data->tcp = ARKIME_TYPE_ALLOC0 (JA4PlusTCP_t);
    } else if (ja4plus_data->tcp) {
        if (ja4plus_data->tcp == JA4PLUS_TCP_DONE)
            return 0;
        ja4plus_tcp = ja4plus_data->tcp;
    } else {
        ja4plus_tcp = ja4plus_data->tcp = ARKIME_TYPE_ALLOC0 (JA4PlusTCP_t);
    }

    ArkimePacket_t      *packet = (ArkimePacket_t *)uw;
    const struct tcphdr *tcphdr = (struct tcphdr *)(packet->pkt + packet->payloadOffset);
    int                  len = packet->payloadLen - 4 * tcphdr->th_off;

    const struct ip       *ip4 = (struct ip *)(packet->pkt + packet->ipOffset);
    const struct ip6_hdr  *ip6 = (struct ip6_hdr *)(packet->pkt + packet->ipOffset);
    const struct tcphdr   *tcp = (struct tcphdr *)(packet->pkt + packet->payloadOffset);

    if (len == 0) {
        if (tcp->th_flags & TH_SYN) {
            if (tcp->th_flags & TH_ACK) {
                if (ja4plus_tcp->synAckTimesCnt < JA4PLUS_SYN_ACK_COUNT) {
                    ja4plus_tcp->synAckTimes[ja4plus_tcp->synAckTimesCnt] = TIMESTAMP_TO_RUSEC(packet->ts);
                    ja4plus_tcp->synAckTimesCnt++;
                }
                if (packet->v6) {
                    ja4plus_tcp->server_ttl = ip6->ip6_hops;
                } else {
                    ja4plus_tcp->server_ttl = ip4->ip_ttl;
                }
                ja4plus_ja4ts(session, ja4plus_tcp, tcp);
            } else {
                ja4plus_tcp->timestampA = TIMESTAMP_TO_RUSEC(packet->ts);
                if (packet->v6) {
                    ja4plus_tcp->client_ttl = ip6->ip6_hops;
                } else {
                    ja4plus_tcp->client_ttl = ip4->ip_ttl;
                }
                ja4plus_ja4t(session, ja4plus_tcp, tcp);
            }
        } else if ((tcp->th_flags & TH_RST) && packet->direction == 1) {
            // Server rst ends the syn-ack sequence, emit once and drop the
            // prefix so a second rst doesn't repeat it
            if (ja4plus_tcp->ja4tsPrefix) {
                ja4plus_ja4ts_rst(session, ja4plus_tcp, TIMESTAMP_TO_RUSEC(packet->ts));
                g_free(ja4plus_tcp->ja4tsPrefix);
                ja4plus_tcp->ja4tsPrefix = NULL;
            }
        } else {
            // C is the client's handshake ack. Both references constrain it to
            // the client side, wireshark with seq==1 && ack==1 and zeek with
            // is_orig, otherwise a bare server ack lands here instead.
            if (packet->direction == 0 && (tcp->th_flags & TH_ACK) && (ja4plus_tcp->timestampC == 0))
                ja4plus_tcp->timestampC = TIMESTAMP_TO_RUSEC(packet->ts);
        }
    } else if (ja4plus_tcp->synAckTimesCnt > 0) {
        if (packet->direction == 0) {
            if (ja4plus_tcp->timestampD == 0) {
                ja4plus_tcp->timestampD = TIMESTAMP_TO_RUSEC(packet->ts);
            } else if (ja4plus_tcp->timestampC != 0 && ja4plus_tcp->timestampE != 0) {
                if (ja4plus_tcp->timestampC >= ja4plus_tcp->synAckTimes[ja4plus_tcp->synAckTimesCnt - 1]) {
                    char ja4l[100];

                    if (arkime_session_has_protocol(session, "http")) {
                        snprintf(ja4l, sizeof(ja4l), "%u_%u_tcp",
                                 (ja4plus_tcp->timestampC - ja4plus_tcp->synAckTimes[ja4plus_tcp->synAckTimesCnt - 1]) / 2,
                                 ja4plus_tcp->client_ttl
                                );
                    } else {
                        uint32_t timestampF = TIMESTAMP_TO_RUSEC(packet->ts);
                        snprintf(ja4l, sizeof(ja4l), "%u_%u_%u",
                                 (ja4plus_tcp->timestampC - ja4plus_tcp->synAckTimes[ja4plus_tcp->synAckTimesCnt - 1]) / 2,
                                 ja4plus_tcp->client_ttl,
                                 (timestampF - ja4plus_tcp->timestampE) / 2
                                );

                        ja4plus_ja4l_delta(session, ja4lDeltaField,
                                           timestampF - ja4plus_tcp->timestampE,
                                           ja4plus_tcp->timestampC - ja4plus_tcp->synAckTimes[ja4plus_tcp->synAckTimesCnt - 1]);
                    }
                    arkime_field_string_add(ja4lField, session, ja4l, -1, TRUE);
                }

                g_free(ja4plus_tcp->ja4tsPrefix);
                ARKIME_TYPE_FREE(JA4PlusTCP_t, ja4plus_data->tcp);
                ja4plus_data->tcp = JA4PLUS_TCP_DONE;
            }
        } else {
            // E is the first server data packet *after* D, not simply the first
            // server data packet. Server first protocols (ftp, smtp, ssh, ...)
            // send before the client does, and without the D check the ja4ls
            // and ja4l timings would be measured against firstPacket instead.
            if (ja4plus_tcp->timestampD != 0 && ja4plus_tcp->timestampE == 0) {
                ja4plus_tcp->timestampE = TIMESTAMP_TO_RUSEC(packet->ts);

                if (ja4plus_tcp->synAckTimes[ja4plus_tcp->synAckTimesCnt - 1] >= ja4plus_tcp->timestampA) {
                    char ja4ls[100];

                    if (arkime_session_has_protocol(session, "http")) {
                        snprintf(ja4ls, sizeof(ja4ls), "%u_%u_tcp",
                                 (ja4plus_tcp->synAckTimes[ja4plus_tcp->synAckTimesCnt - 1] - ja4plus_tcp->timestampA) / 2,
                                 ja4plus_tcp->server_ttl
                                );
                    } else {
                        snprintf(ja4ls, sizeof(ja4ls), "%u_%u_%u",
                                 (ja4plus_tcp->synAckTimes[ja4plus_tcp->synAckTimesCnt - 1] - ja4plus_tcp->timestampA) / 2,
                                 ja4plus_tcp->server_ttl,
                                 (ja4plus_tcp->timestampE - ja4plus_tcp->timestampD) / 2
                                );

                        ja4plus_ja4l_delta(session, ja4lsDeltaField,
                                           ja4plus_tcp->timestampE - ja4plus_tcp->timestampD,
                                           ja4plus_tcp->synAckTimes[ja4plus_tcp->synAckTimesCnt - 1] - ja4plus_tcp->timestampA);
                    }
                    arkime_field_string_add(ja4lsField, session, ja4ls, -1, TRUE);
                }
            }
        }
    }
    return 0;
}
/******************************************************************************/
LOCAL void ja4plus_plugin_save(ArkimeSession_t *session, int final)
{
    JA4PlusData_t *ja4plus_data = session->pluginData[ja4plus_plugin_num];
    if (final && ja4plus_data) {
        if (ja4plus_data->tcp && ja4plus_data->tcp != JA4PLUS_TCP_DONE) {
            g_free(ja4plus_data->tcp->ja4tsPrefix);
            ARKIME_TYPE_FREE(JA4PlusTCP_t, ja4plus_data->tcp);
        }

        if (ja4plus_data->http) {
            JA4PlusHTTP_t *ja4_http = ja4plus_data->http;

            g_free(ja4_http->sorted_cookie_fields);
            g_free(ja4_http->sorted_cookie_values);
            g_string_free(ja4_http->header_value, TRUE);
            g_string_free(ja4_http->header_fields, TRUE);
            ARKIME_TYPE_FREE(JA4PlusHTTP_t, ja4_http);
        }
        ARKIME_TYPE_FREE(JA4PlusData_t, ja4plus_data);
        session->pluginData[ja4plus_plugin_num] = NULL;
    }
}
/******************************************************************************/
LOCAL void *ja4plus_getcb_ja4x(const ArkimeSession_t *session, int UNUSED(pos))
{
#if ARKIME_API_VERSION >= 541
    return arkime_field_certsinfo_get_extra(session, "ja4x");
#else
    return NULL;
#endif
}
/******************************************************************************/
LOCAL void *ja4plus_getcb_ja4x_r(const ArkimeSession_t *session, int UNUSED(pos))
{
#if ARKIME_API_VERSION >= 541
    return arkime_field_certsinfo_get_extra(session, "ja4x_r");
#else
    return NULL;
#endif
}
/******************************************************************************/
LOCAL int ja4plus_dhcp_udp_parser(ArkimeSession_t *session, void *UNUSED(uw), const uint8_t *data, int len)
{
    static const char *messageType[] = {
        "00000",
        "disco",
        "offer",
        "reqst",
        "decln",
        "dpack",
        "dpnak",
        "relse",
        "infor",
        "frenw",
        "lqery",
        "lunas",
        "lunkn",
        "lactv",
        "blklq",
        "lqdon",
        "actlq",
        "lqsta",
        "dhtls"
    };


    if (len < 256 || (data[0] != 1 && data[0] != 2) || ARKIME_SESSION_IS_v6(session) || memcmp(data + 236, "\x63\x82\x53\x63", 4) != 0)
        return 0;

    int msgType = 0;
    char requestIp = 'n';
    char fqdn = 'n';

    char maxSize[7];
    g_strlcpy(maxSize, "0000", sizeof(maxSize));

    char options[1000];
    BSB  oBSB;
    BSB_INIT(oBSB, options, sizeof(options));

    char parameters[1000];
    BSB  pBSB;
    BSB_INIT(pBSB, parameters, sizeof(parameters));

    BSB bsb;
    BSB_INIT(bsb, data, len);

    // header + 236 offset + magic len - 4 skip - u32 import
    BSB_IMPORT_skip(bsb, 4 + 4 + 236 + 4 - 4 - 4);
    while (BSB_REMAINING(bsb) >= 2) {
        int t = 0;
        int l = 0;
        BSB_IMPORT_u08(bsb, t);
        if (t == 255) // End Tag, no length
            break;
        if (t == 0) // Pad, no length
            continue;
        BSB_IMPORT_u08(bsb, l);
        if (BSB_IS_ERROR(bsb) || l > BSB_REMAINING(bsb) || l == 0)
            break;
        const uint8_t *v = 0;
        BSB_IMPORT_ptr(bsb, v, l);

        switch (t) {
        case 50:
            requestIp = 'i';
            continue;
        case 53:
            msgType = v[0];
            continue;
        case 55: // Parameter Request List
            for (int i = 0; i < l; i++) {
                if (i > 0) {
                    BSB_EXPORT_u08(pBSB, '-');
                }
                BSB_EXPORT_sprintf(pBSB, "%d", v[i]);
            }
            break;
        case 57: // Maximum DHCP Message Size
            if (l == 2) {
                uint16_t size = 0;
                memcpy(&size, v, 2);
                snprintf(maxSize, sizeof(maxSize), "%04d", ntohs(size));
            }
            break;
        case 81:
            fqdn = 'd';
            continue;
        } /* switch */

        if (BSB_LENGTH(oBSB) > 0) {
            BSB_EXPORT_u08(oBSB, '-');
        }
        BSB_EXPORT_sprintf(oBSB, "%d", t);
    }

    if (BSB_LENGTH(oBSB) <= 0) {
        snprintf(options, sizeof(options), "00");
    } else {
        options[MIN(sizeof(options) - 1, (unsigned long)BSB_LENGTH(oBSB))] = 0;
    }
    if (BSB_LENGTH(pBSB) <= 0) {
        snprintf(parameters, sizeof(parameters), "00");
    } else {
        parameters[MIN(sizeof(parameters) - 1, (unsigned long)BSB_LENGTH(pBSB))] = 0;
    }
    char ja4d[2048];
    if (msgType < ARRAY_LEN(messageType))
        snprintf(ja4d, sizeof(ja4d), "%s%s%c%c_%s_%s", messageType[msgType], maxSize, requestIp, fqdn, options, parameters);
    else
        snprintf(ja4d, sizeof(ja4d), "%05d%s%c%c_%s_%s", msgType, maxSize, requestIp, fqdn, options, parameters);

    arkime_field_string_add(ja4dField, session, ja4d, -1, TRUE);

    return 0;
}

/******************************************************************************/
LOCAL int ja4plus_dhcpv6_udp_parser(ArkimeSession_t *session, void *UNUSED(uw), const uint8_t *data, int len)
{
    static const char *messageType[] = {
        "00000",
        "solct",
        "advrt",
        "reqst",
        "confm",
        "renew",
        "rebnd",
        "reply",
        "relse",
        "decln",
        "recon",
        "inreq",
        "rlayf",
        "rlayr",
        "query",
        "qrply",
        "qdone",
        "qdata",
        "rereq",
        "rrply",
        "v4qry",
        "v4res",
        "acqry",
        "sttls",
        "bdudp",
        "brply",
        "poreq",
        "pores",
        "urqst",
        "ureqa",
        "udone",
        "conne",
        "connr",
        "dconn",
        "state",
        "conta",
        "arinf",
        "arrep"
    };


    // Minimum: msg-type+txn-id (4) or relay header (34), plus one option header
    if (len < 8 || data[0] == 0)
        return 0;

    int msgType = data[0];

    if ((msgType == 12 || msgType == 13) && len < 38)
        return 0;
    char requestIp = 'n';
    char fqdn = 'n';

    char maxSize[7];
    g_strlcpy(maxSize, "0000", sizeof(maxSize));

    char options[1000];
    BSB  oBSB;
    BSB_INIT(oBSB, options, sizeof(options));

    char parameters[1000];
    BSB  pBSB;
    BSB_INIT(pBSB, parameters, sizeof(parameters));

    BSB bsb;
    BSB_INIT(bsb, data, len);

    // Relay-Forward/Relay-Reply have msg-type, hop-count, link-address and
    // peer-address before the options; everything else just msg-type + txn-id
    if (msgType == 12 || msgType == 13)
        BSB_IMPORT_skip(bsb, 34);
    else
        BSB_IMPORT_skip(bsb, 4);
    while (BSB_REMAINING(bsb) >= 4) {
        int t = 0;
        int l = 0;
        BSB_IMPORT_u16(bsb, t);
        BSB_IMPORT_u16(bsb, l);
        if (BSB_IS_ERROR(bsb) || l > BSB_REMAINING(bsb))
            break;
        uint8_t *v = 0;
        BSB_IMPORT_ptr(bsb, v, l);

        if (BSB_LENGTH(oBSB) > 0) {
            BSB_EXPORT_u08(oBSB, '-');
        }
        BSB_EXPORT_sprintf(oBSB, "%d", t);

        switch (t) {
        case 1:
            snprintf(maxSize, sizeof(maxSize), "%04d", l);
            break;
        case 4:
            // IA_TA presence keys the requested-ip flag (matches the FoxIO
            // wireshark reference dhcpv6.iata handling)
            requestIp = 'i';
            break;
        case 6:
            for (int i = 0; i < l - 1; i += 2) {
                uint16_t option;
                memcpy(&option, v + i, 2);
                if (i > 0) {
                    BSB_EXPORT_u08(pBSB, '-');
                }
                BSB_EXPORT_sprintf(pBSB, "%d", ntohs(option));
            }
            break;
        case 3:
        case 25: {
            BSB ibsb;
            BSB_INIT(ibsb, v, l);
            BSB_IMPORT_skip(ibsb, 12);
            while (BSB_REMAINING(ibsb) >= 4) {
                int it = 0;
                int il = 0;
                BSB_IMPORT_u16(ibsb, it);
                BSB_IMPORT_u16(ibsb, il);
                if (BSB_IS_ERROR(ibsb) || il > BSB_REMAINING(ibsb))
                    break;
                BSB_IMPORT_skip(ibsb, il);
                if (BSB_LENGTH(oBSB) > 0) {
                    BSB_EXPORT_u08(oBSB, '-');
                }
                BSB_EXPORT_sprintf(oBSB, "%d", it);
            }
            break;
        }
        case 39: {
            // FQDN flag keys on a client domain name being present (matches
            // the FoxIO wireshark reference dhcpv6.client_domain), not on
            // the flags byte being 0
            if (l > 1)
                fqdn = 'd';
            break;
        }
        } /* switch */
    }

    if (BSB_LENGTH(oBSB) <= 0) {
        snprintf(options, sizeof(options), "00");
    } else {
        options[MIN(sizeof(options) - 1, (unsigned long)BSB_LENGTH(oBSB))] = 0;
    }
    if (BSB_LENGTH(pBSB) <= 0) {
        snprintf(parameters, sizeof(parameters), "00");
    } else {
        parameters[MIN(sizeof(parameters) - 1, (unsigned long)BSB_LENGTH(pBSB))] = 0;
    }
    char ja4d6[2048];
    if (msgType < ARRAY_LEN(messageType))
        snprintf(ja4d6, sizeof(ja4d6), "%s%s%c%c_%s_%s", messageType[msgType], maxSize, requestIp, fqdn, options, parameters);
    else
        snprintf(ja4d6, sizeof(ja4d6), "%05d%s%c%c_%s_%s", msgType, maxSize, requestIp, fqdn, options, parameters);
    arkime_field_string_add(ja4d6Field, session, ja4d6, -1, TRUE);

    return 0;
}
/******************************************************************************/
/* JA4N - NTP fingerprint
 *
 * (mode)(version)-(leap)-(stratum)-(poll)-(precision)-(rootdelay)(rootdisp)_
 * (ref)(org)(rec)(xmt)_(refid)_(poll secs)
 *
 * stratum is a code, 0 when the packet has no stratum and 1 for any real one
 *
 * ex: c4-0-1-10-25-22_1111_ipv4_1024
 */
#define JA4PLUS_NTP_EPOCH 2208988800LL
#define JA4PLUS_NTP_RECENT (30LL * 24 * 3600)

/******************************************************************************/
/* Root delay/dispersion are 16.16 fixed point, bucketed as zero / exactly 1s / other */
LOCAL char ja4plus_ntp_root_code(uint32_t val)
{
    if (val == 0)
        return '0';
    if (val == 0x00010000)
        return '1';
    return '2';
}
/******************************************************************************/
/* Unix epoch seconds of an NTP timestamp, an unset timestamp stays 0 */
LOCAL int64_t ja4plus_ntp_epoch(uint64_t ts)
{
    if (ts == 0)
        return 0;
    return (int64_t)(ts >> 32) - JA4PLUS_NTP_EPOCH;
}
/******************************************************************************/
/* Multiply a little endian decimal digit array by m, returns the new length */
LOCAL int ja4plus_ntp_mul(uint8_t *digits, int len, int m)
{
    int carry = 0;

    for (int i = 0; i < len; i++) {
        const int v = digits[i] * m + carry;
        digits[i] = v % 10;
        carry = v / 10;
    }
    while (carry) {
        digits[len++] = carry % 10;
        carry /= 10;
    }
    return len;
}
/******************************************************************************/
/* Poll is a log2 seconds exponent, rendered as the decimal seconds with the
 * point removed, so -1 is 05, -2 is 025 and -4 is 00625. 2^-n is 5^n over 10^n,
 * which is exactly n decimal digits, hence the zero padding.
 */
LOCAL void ja4plus_ntp_poll_secs(int8_t poll, char *out, int outlen)
{
    uint8_t digits[160];  // 5^128 is 90 digits, 2^127 is 39
    int     len = 1;

    digits[0] = 1;

    const int n = (poll < 0) ? -poll : 0;
    for (int i = 0; i < (poll < 0 ? n : poll); i++) {
        len = ja4plus_ntp_mul(digits, len, poll < 0 ? 5 : 2);
    }

    int pos = 0;
    if (poll < 0) {
        out[pos++] = '0';
        for (int i = len; i < n && pos < outlen - 1; i++) {
            out[pos++] = '0';
        }
    }
    for (int i = len - 1; i >= 0 && pos < outlen - 1; i--) {
        out[pos++] = '0' + digits[i];
    }
    out[pos] = 0;
}
/******************************************************************************/
/* now is capture time, not wall clock, so the fingerprint is reproducible */
LOCAL char ja4plus_ntp_ts_code(uint64_t ts, int64_t now)
{
    if (ts == 0)
        return '0';

    int64_t diff = ja4plus_ntp_epoch(ts) - now;
    if (diff < 0)
        diff = -diff;
    return (diff <= JA4PLUS_NTP_RECENT) ? '1' : '2';
}
/******************************************************************************/
/* Like wireshark packet-ntp.c, the meaning comes from stratum alone and never
 * from the bytes, but unlike wireshark the name isn't checked against the
 * known kiss-o'-death/clock lists, it is just passed through
 */
LOCAL void ja4plus_ntp_refid(const ArkimeSession_t *session, const uint8_t *refId, uint8_t stratum, char out[5])
{
    // 0 is a kiss-o'-death code, 1 a reference clock name, anything else an
    // address. A literal IPv4 address and the first 4 bytes of the md5 of an
    // IPv6 address are indistinguishable, so go by the session's own family
    if (stratum > 1) {
        memcpy(out, ARKIME_SESSION_IS_v6(session) ? "ipv6" : "ipv4", 5);
        return;
    }

    int printable = 0, nulls = 0;
    for (int i = 0; i < 4; i++) {
        if (isprint(refId[i]))
            printable++;
        else if (refId[i] == 0)
            nulls++;
    }

    if (printable == 4) {
        memcpy(out, refId, 4);
    } else if (printable == 3 && nulls == 1) {
        for (int i = 0; i < 4; i++) {
            out[i] = refId[i] ? refId[i] : '0';
        }
    } else {
        // Always 4 printable chars, so an all zero refid lands here as 0000
        memcpy(out, arkime_char_to_hexstr[refId[0]], 2);
        memcpy(out + 2, arkime_char_to_hexstr[refId[1]], 2);
    }
    out[4] = 0;
}
/******************************************************************************/
LOCAL int ja4plus_ntp_parser(ArkimeSession_t *session, void UNUSED(*uw), const uint8_t *data, int len, int UNUSED(which))
{
    // Short mode 6/7 control packets have a different header and no
    // fingerprintable fields
    if (len < 48)
        return 0;

    static const char modeCodes[] = "0apcsbn7";

    uint8_t        flags = 0, stratum = 0, poll = 0, precision = 0;
    uint32_t       rootDelay = 0, rootDisp = 0;
    uint64_t       refTs = 0, orgTs = 0, recTs = 0, xmtTs = 0;
    const uint8_t *refId = NULL;

    BSB bsb;
    BSB_INIT(bsb, data, len);

    BSB_IMPORT_u08(bsb, flags);
    BSB_IMPORT_u08(bsb, stratum);
    BSB_IMPORT_u08(bsb, poll);
    BSB_IMPORT_u08(bsb, precision);
    BSB_IMPORT_u32(bsb, rootDelay);
    BSB_IMPORT_u32(bsb, rootDisp);
    BSB_IMPORT_ptr(bsb, refId, 4);
    BSB_IMPORT_u64(bsb, refTs);
    BSB_IMPORT_u64(bsb, orgTs);
    BSB_IMPORT_u64(bsb, recTs);
    BSB_IMPORT_u64(bsb, xmtTs);

    if (BSB_IS_ERROR(bsb) || !refId)
        return 0;

    char refIdStr[5];
    ja4plus_ntp_refid(session, refId, stratum, refIdStr);

    const int64_t now = session->firstPacket.tv_sec;

    char pollSecs[160];
    ja4plus_ntp_poll_secs((int8_t)poll, pollSecs, sizeof(pollSecs));

    char ja4n[256];
    snprintf(ja4n, sizeof(ja4n), "%c%u-%u-%u-%d-%u-%c%c_%c%c%c%c_%s_%s",
             modeCodes[flags & 0x07],
             (flags >> 3) & 0x07u,   // version
             (flags >> 6) & 0x03u,   // leap
             stratum ? 1u : 0u,   // code, not the raw stratum
             (int8_t)poll,   // log2 seconds, signed per RFC 5905
             256u - precision,
             ja4plus_ntp_root_code(rootDelay),
             ja4plus_ntp_root_code(rootDisp),
             ja4plus_ntp_ts_code(refTs, now),
             ja4plus_ntp_ts_code(orgTs, now),
             ja4plus_ntp_ts_code(recTs, now),
             ja4plus_ntp_ts_code(xmtTs, now),
             refIdStr,
             pollSecs
            );

    arkime_field_string_add(ja4nField, session, ja4n, -1, TRUE);
    return 0;
}
/******************************************************************************/
/* Same checks as parsers/ntp.c, kept separate so ja4n doesn't depend on the
 * ntp parser being enabled
 */
LOCAL void ja4plus_ntp_classify(ArkimeSession_t *session, const uint8_t *data, int len, int UNUSED(which), void UNUSED(*uw))
{
    if (len < 48)
        return;

    if (data[1] > 16)  // stratum
        return;

    const uint8_t version = (data[0] >> 3) & 0x07;
    const uint8_t mode = data[0] & 0x07;

    if (version < 1 || version > 4 || mode == 0)
        return;

    // Called once per direction, and twice more when both ports are 123, but
    // arkime_parsers_register2 drops the duplicates
    arkime_parsers_register(session, ja4plus_ntp_parser, 0, 0);
}
/******************************************************************************/
LOCAL uint32_t ja4plus_dhcp_packet(ArkimeSession_t *session, const uint8_t *d, int l, void UNUSED(*uw))
{
    if (IN6_IS_ADDR_V4MAPPED(&session->addr1)) {
        return ja4plus_dhcp_udp_parser(session, NULL, d, l);
    } else {
        return ja4plus_dhcpv6_udp_parser(session, NULL, d, l);
    }
}
/******************************************************************************/
void arkime_plugin_init()
{
    LOG("JA4+ plugin loaded");

    ja4plus_plugin_num = arkime_plugins_register("ja4plus", TRUE);

    arkime_plugins_set_cb("ja4plus",
                          NULL,
                          NULL,
                          NULL,
                          NULL,
                          ja4plus_plugin_save,
                          NULL,
                          NULL,
                          NULL);

    arkime_plugins_set_http_ext_cb("ja4plus",
                                   NULL,
                                   NULL,
                                   NULL,
                                   ja4plus_http_header_field_raw,
                                   ja4plus_http_header_value,
                                   NULL,
                                   NULL,
                                   ja4plus_http_complete);

    ja4Raw = arkime_config_boolean(NULL, "ja4Raw", FALSE);
    ja4hOmitZeroSections = arkime_config_boolean(NULL, "ja4hOmitZeroSections", FALSE);
    ja4nEnable = arkime_config_boolean(NULL, "ja4nEnable", FALSE);

    arkime_parsers_add_named_func("tls_process_server_hello", ja4plus_tls_process_server_hello);
    arkime_parsers_add_named_func("dtls_process_server_hello", ja4plus_dtls_process_server_hello);
    arkime_parsers_add_named_func("tls_process_certificate_wInfo", ja4plus_process_certificate_wInfo);
    arkime_parsers_add_named_func("ssh_counting200", ja4plus_ssh_ja4ssh);
    arkime_parsers_add_named_func("tcp_raw_packet", ja4plus_tcp_raw_packet);
    arkime_parsers_add_named_func("dhcp_packet", ja4plus_dhcp_packet);

    if (ja4nEnable)
        arkime_parsers_classifier_register_port("ja4n", NULL, 123, ARKIME_PARSERS_PORT_UDP, ja4plus_ntp_classify);

    ja4sField = arkime_field_define("tls", "lotermfield",
                                    "tls.ja4s", "JA4s", "tls.ja4s",
                                    "SSL/TLS JA4s field",
                                    ARKIME_FIELD_TYPE_STR_GHASH,  ARKIME_FIELD_FLAG_CNT,
                                    (char *)NULL);

    ja4sRawField = arkime_field_define("tls", "lotermfield",
                                       "tls.ja4s_r", "JA4s_r", "tls.ja4s_r",
                                       "SSL/TLS JA4s raw field",
                                       ARKIME_FIELD_TYPE_STR_GHASH,  ARKIME_FIELD_FLAG_CNT,
                                       (char *)NULL);


    arkime_field_define("cert", "termfield",
                        "cert.ja4x", "JA4x", "cert.ja4x",
                        "JA4x",
                        0, ARKIME_FIELD_FLAG_FAKE,
                        (char *)NULL);

    arkime_field_by_exp_add_internal("cert.ja4x", ARKIME_FIELD_TYPE_STR_ARRAY, ja4plus_getcb_ja4x, NULL);

    arkime_field_define("cert", "termfield",
                        "cert.ja4x_r", "JA4x_r", "cert.ja4x_r",
                        "JA4x_r",
                        0, ARKIME_FIELD_FLAG_FAKE,
                        (char *)NULL);

    arkime_field_by_exp_add_internal("cert.ja4x_r", ARKIME_FIELD_TYPE_STR_ARRAY, ja4plus_getcb_ja4x_r, NULL);

    ja4sshField = arkime_field_define("ssh", "lotermfield",
                                      "ssh.ja4ssh", "JA4ssh", "ssh.ja4ssh",
                                      "SSH JA4ssh field",
                                      ARKIME_FIELD_TYPE_STR_ARRAY,  ARKIME_FIELD_FLAG_CNT | ARKIME_FIELD_FLAG_DIFF_FROM_LAST,
                                      (char *)NULL);

    ja4lField = arkime_field_define("tcp", "lotermfield",
                                    "tcp.ja4l", "JA4l", "tcp.ja4l",
                                    "JA4 Latency Client field",
                                    ARKIME_FIELD_TYPE_STR,  0,
                                    (char *)NULL);

    ja4lDeltaField = arkime_field_define("tcp", "lotermfield",
                                         "tcp.ja4l-delta", "JA4l-Delta", "tcp.ja4l-delta",
                                         "JA4 Latency Client Delta field",
                                         ARKIME_FIELD_TYPE_STR,  0,
                                         (char *)NULL);

    ja4lsField = arkime_field_define("tcp", "lotermfield",
                                     "tcp.ja4ls", "JA4ls", "tcp.ja4ls",
                                     "JA4 Latency Server field",
                                     ARKIME_FIELD_TYPE_STR,  0,
                                     (char *)NULL);

    ja4lsDeltaField = arkime_field_define("tcp", "lotermfield",
                                          "tcp.ja4ls-delta", "JA4ls-Delta", "tcp.ja4ls-delta",
                                          "JA4 Latency Server Delta field",
                                          ARKIME_FIELD_TYPE_STR,  0,
                                          (char *)NULL);

    ja4tsField = arkime_field_define("tcp", "lotermfield",
                                     "tcp.ja4ts", "JA4ts", "tcp.ja4ts",
                                     "JA4 TCP Server field",
                                     ARKIME_FIELD_TYPE_STR_GHASH,  ARKIME_FIELD_FLAG_CNT,
                                     (char *)NULL);

    ja4tField = arkime_field_define("tcp", "lotermfield",
                                    "tcp.ja4t", "JA4t", "tcp.ja4t",
                                    "JA4 TCP Client field",
                                    ARKIME_FIELD_TYPE_STR_GHASH,  ARKIME_FIELD_FLAG_CNT,
                                    (char *)NULL);

    ja4hField = arkime_field_define("http", "lotermfield",
                                    "http.ja4h", "JA4h", "http.ja4h",
                                    "HTTP JA4h field",
                                    ARKIME_FIELD_TYPE_STR_GHASH,  ARKIME_FIELD_FLAG_CNT,
                                    (char *)NULL);

    ja4hRawField = arkime_field_define("http", "lotermfield",
                                       "http.ja4h_r", "JA4h_r", "http.ja4h_r",
                                       "HTTP JA4h Raw field",
                                       ARKIME_FIELD_TYPE_STR_GHASH,  ARKIME_FIELD_FLAG_CNT,
                                       (char *)NULL);

    ja4dField = arkime_field_define("dhcp", "lotermfield",
                                    "dhcp.ja4d", "JA4d", "dhcp.ja4d",
                                    "DHCP JA4d field",
                                    ARKIME_FIELD_TYPE_STR_GHASH,  ARKIME_FIELD_FLAG_CNT,
                                    (char *)NULL);

    ja4d6Field = arkime_field_define("dhcp", "lotermfield",
                                     "dhcp.ja4d6", "JA4d6", "dhcp.ja4d6",
                                     "DHCP JA4d6 field",
                                     ARKIME_FIELD_TYPE_STR_GHASH,  ARKIME_FIELD_FLAG_CNT,
                                     (char *)NULL);

    // termfield, not lotermfield, since the reference id section is case sensitive
    ja4nField = arkime_field_define("ja4n", "termfield",
                                    "ntp.ja4n", "JA4n", "ntp.ja4n",
                                    "NTP JA4n field",
                                    ARKIME_FIELD_TYPE_STR_GHASH,  ARKIME_FIELD_FLAG_CNT,
                                    (char *)NULL);

    int t;
    for (t = 0; t < config.packetThreads; t++) {
        checksums256[t] = g_checksum_new(G_CHECKSUM_SHA256);
    }
}
