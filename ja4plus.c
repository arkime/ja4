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
LOCAL int                    ja4lsField;
LOCAL int                    ja4tField;
LOCAL int                    ja4tsField;
LOCAL int                    ja4hField;
LOCAL int                    ja4hRawField;
LOCAL int                    ja4dField;
LOCAL int                    ja4d6Field;


LOCAL int                    ja4plus_plugin_num;
LOCAL GChecksum             *checksums256[ARKIME_MAX_PACKET_THREADS];
extern uint8_t               arkime_char_to_hexstr[256][3];
LOCAL gboolean               ja4Raw;
LOCAL gboolean               ja4hOmitZeroSections;

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
    char      *value;
    uint16_t   flen;
    uint16_t   vlen;
} JA4PlusCookie_t;

#define TIMESTAMP_TO_RUSEC(ts) (ts.tv_sec - session->firstPacket.tv_sec) * 1000000 + (ts.tv_usec - session->firstPacket.tv_usec)

/******************************************************************************/
LOCAL int cookie_cmp(const void *a, const void *b)
{
    return strcmp(((JA4PlusCookie_t *)a)->field, ((JA4PlusCookie_t *)b)->field);
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
            char *equal = memchr(start, '=', end - start);
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

                if (cookies[i].value) {
                    *(fvpos++) = '=';
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
    /* See thirdparty/http_parser.h */
#define HTTP_METHODS 26
    static const char *methods[HTTP_METHODS] = {
        "de",
        "ge",
        "he",
        "po",
        "pu",

        "co",
        "op",
        "tr",

        "cy",
        "lo",
        "ml",
        "mo",
        "pf",
        "pp",
        "se",
        "uo",

        "rp",
        "ma",
        "ct",
        "me",

        "ms",
        "no",
        "su",
        "un",

        "pa",
        "pr"
    };

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

    const char *method = parser->method < HTTP_METHODS ? methods[parser->method] : "00";
    GChecksum *const checksum = checksums256[session->thread];
    snprintf(ja4h, sizeof(ja4h), "%s%d%d%c%c%02d%4.4s_",
             method,
             parser->http_major,
             parser->http_minor,
             (ja4_http->cookies == 0) ? 'n' : 'c',
             (ja4_http->referer == 0) ? 'n' : 'r',
             ja4_http->headers,
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
    } else if (ja4hOmitZeroSections) {
        g_strlcpy(ja4h + 26, "_", sizeof(ja4h) - 26);
    } else {
        g_strlcpy(ja4h + 26, "000000000000_000000000000", sizeof(ja4h) - 26);
    }
    ja4h[51] = 0;
    arkime_field_string_add(ja4hField, session, ja4h, 51, TRUE);

    if (ja4Raw) {
        char ja4h_r[1024];

        snprintf(ja4h_r, sizeof(ja4h_r), "%s%d%d%c%c%02d%4.4s_%s_%s_%s",
                 method,
                 parser->http_major,
                 parser->http_minor,
                 (ja4_http->cookies == 0) ? 'n' : 'c',
                 (ja4_http->referer == 0) ? 'n' : 'r',
                 ja4_http->headers,
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
        ja4alpn[0] = tolower(alpn[0]);
        ja4alpn[1] = tolower(alpn[len]);
    } else {
        ja4alpn[0] = arkime_char_to_hexstr[alpn[0]][0];
        ja4alpn[1] = arkime_char_to_hexstr[alpn[len]][1];
    }
}

/******************************************************************************/
LOCAL uint32_t ja4plus_dtls_process_server_hello(ArkimeSession_t *session, const uint8_t *data, int len, void UNUSED(*uw))
{
    // https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4S.md
    uint8_t  ja4NumExtensions = 0;
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

            if (ja4plus_is_grease_value(etype)) {
                BSB_IMPORT_skip (ebsb, elen);
                continue;
            }

            ja4Extensions[ja4NumExtensions] = etype;
            ja4NumExtensions++;

            if (elen > BSB_REMAINING(ebsb))
                break;

            if (etype == 0x2b && elen == 2) { // etype 0x2b is supported version
                BSB_IMPORT_u16(ebsb, supportedver);

                supportedver = MAX(ver, supportedver);
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

    char tmpBuf[5 * 256];
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
    uint8_t  ja4NumExtensions = 0;
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

            if (ja4plus_is_grease_value(etype)) {
                BSB_IMPORT_skip (ebsb, elen);
                continue;
            }

            ja4Extensions[ja4NumExtensions] = etype;
            ja4NumExtensions++;

            if (elen > BSB_REMAINING(ebsb))
                break;

            if (etype == 0x2b && elen == 2) { // etype 0x2b is supported version
                BSB_IMPORT_u16(ebsb, supportedver);

                supportedver = MAX(ver, supportedver);
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

    char tmpBuf[5 * 256];
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
    char ja4x_r[1000];
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
    if (ja4Raw) {
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
LOCAL void ja4plus_ja4ts(ArkimeSession_t *session, const JA4PlusTCP_t *data, const struct tcphdr *tcph)
{
    uint8_t        *p = (uint8_t *)tcph + 20;
    const uint8_t  *end = (uint8_t *)tcph + tcph->th_off * 4;
    uint16_t        mss = 0xffff;
    uint8_t         window_scale = 0xff;

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
            if (next == 2)
                BSB_IMPORT_u16(hbsb, mss);
            else if (next == 3)
                BSB_IMPORT_u08(hbsb, window_scale);
            else
                BSB_IMPORT_skip(hbsb, size - 2);
        }

        BSB_EXPORT_rewind(obsb, 1); // remove last -
    }

    if (mss == 0xffff) {
        BSB_EXPORT_cstr(obsb, "_00");
    } else {
        BSB_EXPORT_sprintf(obsb, "_%d", mss);
    }

    if (window_scale == 0xff) {
        BSB_EXPORT_cstr(obsb, "_00");
    } else {
        BSB_EXPORT_sprintf(obsb, "_%d", window_scale);
    }

    if (data->synAckTimesCnt > 1) {
        BSB_EXPORT_cstr(obsb, "_");
        for (int i = 1; i < data->synAckTimesCnt; i++) {
            BSB_EXPORT_sprintf(obsb, "%.0f-", round ((data->synAckTimes[i] - data->synAckTimes[i - 1]) / 1000000));
        }
        BSB_EXPORT_rewind(obsb, 1); // remove last -
    }

    BSB_EXPORT_u08(obsb, 0);
    arkime_field_string_add(ja4tsField, session, obuf, -1, TRUE);
}
/******************************************************************************/
LOCAL void ja4plus_ja4t(ArkimeSession_t *session, JA4PlusTCP_t UNUSED(*data), const struct tcphdr *tcph)
{
    uint8_t        *p = (uint8_t *)tcph + 20;
    const uint8_t  *end = (uint8_t *)tcph + tcph->th_off * 4;
    uint16_t        mss = 0xffff;
    uint8_t         window_scale = 0xff;

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
            if (next == 2)
                BSB_IMPORT_u16(hbsb, mss);
            else if (next == 3)
                BSB_IMPORT_u08(hbsb, window_scale);
            else
                BSB_IMPORT_skip(hbsb, size - 2);
        }

        BSB_EXPORT_rewind(obsb, 1); // remove last -
    }

    if (mss == 0xffff) {
        BSB_EXPORT_cstr(obsb, "_00");
    } else {
        BSB_EXPORT_sprintf(obsb, "_%d", mss);
    }

    if (window_scale == 0xff) {
        BSB_EXPORT_cstr(obsb, "_00");
    } else {
        BSB_EXPORT_sprintf(obsb, "_%d", window_scale);
    }

    BSB_EXPORT_u08(obsb, 0);
    arkime_field_string_add(ja4tField, session, obuf, -1, TRUE);
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
    struct tcphdr       *tcphdr = (struct tcphdr *)(packet->pkt + packet->payloadOffset);
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
        } else {
            if ((tcp->th_flags & TH_ACK) && (ja4plus_tcp->timestampC == 0))
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
                    }
                    arkime_field_string_add(ja4lField, session, ja4l, -1, TRUE);
                }

                ARKIME_TYPE_FREE(JA4PlusTCP_t, ja4plus_data->tcp);
                ja4plus_data->tcp = JA4PLUS_TCP_DONE;
            }
        } else {
            if (ja4plus_tcp->timestampE == 0) {
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
        if (ja4plus_data->tcp && ja4plus_data->tcp != JA4PLUS_TCP_DONE)
            ARKIME_TYPE_FREE(JA4PlusTCP_t, ja4plus_data->tcp);

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
    static char *messageType[] = {
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


    if (len < 256 || (data[0] != 1 && data[0] != 2) || ARKIME_SESSION_v6(session) || memcmp(data + 236, "\x63\x82\x53\x63", 4) != 0)
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
                snprintf(maxSize, sizeof(maxSize), "%04d", htons(size));
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

    options[BSB_LENGTH(oBSB)] = 0;
    if (BSB_LENGTH(pBSB) == 0) {
        snprintf(parameters, sizeof(parameters), "00");
    } else {
        parameters[BSB_LENGTH(pBSB)] = 0;
    }
    char ja4d[2048];
    if (msgType <= 18)
        snprintf(ja4d, sizeof(ja4d), "%s%s%c%c_%s_%s", messageType[msgType], maxSize, requestIp, fqdn, options, parameters);
    else
        snprintf(ja4d, sizeof(ja4d), "%05d%s%c%c_%s_%s", msgType, maxSize, requestIp, fqdn, options, parameters);

    arkime_field_string_add(ja4dField, session, ja4d, -1, TRUE);

    return 0;
}

/******************************************************************************/
LOCAL int ja4plus_dhcpv6_udp_parser(ArkimeSession_t *session, void *UNUSED(uw), const uint8_t *data, int len)
{
    static char *messageType[] = {
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


    if (len < 46 || data[0] == 0 ||  data[0] > 11)
        return 0;

    int msgType = data[0];
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
        case 6:
            for (int i = 0; i < l; i += 2) {
                uint16_t option;
                memcpy(&option, v + i, 2);
                if (i > 0) {
                    BSB_EXPORT_u08(pBSB, '-');
                }
                BSB_EXPORT_sprintf(pBSB, "%d", htons(option));
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
                if (t == 3 && it == 3) {
                    requestIp = 'i';
                }
            }
            break;
        }
        case 39: {
            uint16_t flags = 0;
            BSB ibsb;
            BSB_INIT(ibsb, v, l);
            BSB_IMPORT_u16(ibsb, flags);
            if (!BSB_IS_ERROR(ibsb) && flags == 0)
                fqdn = 'd';
            break;
        }
        } /* switch */
    }

    options[BSB_LENGTH(oBSB)] = 0;
    if (BSB_LENGTH(pBSB) == 0) {
        snprintf(parameters, sizeof(parameters), "00");
    } else {
        parameters[BSB_LENGTH(pBSB)] = 0;
    }
    char ja4d6[2048];
    if (msgType <= 18)
        snprintf(ja4d6, sizeof(ja4d6), "%s%s%c%c_%s_%s", messageType[msgType], maxSize, requestIp, fqdn, options, parameters);
    else
        snprintf(ja4d6, sizeof(ja4d6), "%05d%s%c%c_%s_%s", msgType, maxSize, requestIp, fqdn, options, parameters);
    arkime_field_string_add(ja4d6Field, session, ja4d6, -1, TRUE);

    return 0;
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

    arkime_parsers_add_named_func("tls_process_server_hello", ja4plus_tls_process_server_hello);
    arkime_parsers_add_named_func("dtls_process_server_hello", ja4plus_dtls_process_server_hello);
    arkime_parsers_add_named_func("tls_process_certificate_wInfo", ja4plus_process_certificate_wInfo);
    arkime_parsers_add_named_func("ssh_counting200", ja4plus_ssh_ja4ssh);
    arkime_parsers_add_named_func("tcp_raw_packet", ja4plus_tcp_raw_packet);
    arkime_parsers_add_named_func("dhcp_packet", ja4plus_dhcp_packet);

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

    ja4lsField = arkime_field_define("tcp", "lotermfield",
                                     "tcp.ja4ls", "JA4ls", "tcp.ja4ls",
                                     "JA4 Latency Server field",
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
    int t;
    for (t = 0; t < config.packetThreads; t++) {
        checksums256[t] = g_checksum_new(G_CHECKSUM_SHA256);
    }
}
