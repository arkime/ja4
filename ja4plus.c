/* ja4plus.c  -- ja4+ implementation for ja4s and ja4x
 *
 * Copyright 2023 AOL Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * This software requires a license to use. See
 * https://github.com/FoxIO-LLC/ja4#licensing
 * https://github.com/FoxIO-LLC/ja4/blob/main/License%20FAQ.md
 */

#include "arkime.h"

extern ArkimeConfig_t        config;
LOCAL int                    ja4sField;
LOCAL int                    ja4sshField;
LOCAL GChecksum             *checksums256[ARKIME_MAX_PACKET_THREADS];
extern uint8_t               arkime_char_to_hexstr[256][3];

// keep this in sync with capture/parsers/ssh.c
typedef struct {
    uint16_t  modes[2];
    uint16_t  packets[2];
} SSHJA4_t;

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
LOCAL void ja4plus_ja4_version(uint16_t ver, char vstr[3])
{
    switch (ver) {
    case 0x0100:
        memcpy(vstr, "s1", 3);
        break;
    case 0x0200:
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
    /* case 0x7f00 ... 0x7fff:
        memcpy(vstr, "13", 3);
        break; */
    default:
        memcpy(vstr, "00", 3);
        break;
    }
}
/******************************************************************************/
LOCAL uint32_t ja4plus_process_server_hello(ArkimeSession_t *session, const uint8_t *data, int len, void UNUSED(*uw))
{
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

    if(BSB_IS_ERROR(bsb))
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
                BSB bsb;
                BSB_IMPORT_bsb (ebsb, bsb, elen);

                BSB_IMPORT_skip (bsb, 2); // len
                uint8_t plen = 0;
                BSB_IMPORT_u08 (bsb, plen); // len
                unsigned char *pstr = NULL;
                BSB_IMPORT_ptr (bsb, pstr, plen);
                if (plen > 0 && pstr && !BSB_IS_ERROR(bsb)) {
                    ja4ALPN[0] = pstr[0];
                    ja4ALPN[1] = pstr[plen - 1];
                }
                continue; // Already processed ebsb above
            }
            BSB_IMPORT_skip (ebsb, elen);
        }
    }

    // JA4s Creation
    char vstr[3];
    ja4plus_ja4_version(supportedver, vstr);

    char ja4[26];
    ja4[25] = 0;
    ja4[0] = (session->ipProtocol == IPPROTO_TCP) ? 't' : 'q';
    ja4[1] = vstr[0];
    ja4[2] = vstr[1];
    ja4[3] = (ja4NumExtensions / 10) + '0';
    ja4[4] = (ja4NumExtensions % 10) + '0';
    ja4[5] = ja4ALPN[0];
    ja4[6] = ja4ALPN[1];
    ja4[7] = '_';
    memcpy(ja4 + 8, cipherHex, 4);
    ja4[12] = '_';

    char tmpBuf[10 * 256];
    BSB tmpBSB;

    BSB_INIT(tmpBSB, tmpBuf, sizeof(tmpBuf));
    for (int i = 0; i < ja4NumExtensions; i++) {
        BSB_EXPORT_sprintf(tmpBSB, "%04x,", ja4Extensions[i]);
    }
    BSB_EXPORT_rewind(tmpBSB, 1); // Remove last ,

    GChecksum *const checksum = checksums256[session->thread];

    if (BSB_LENGTH(tmpBSB) > 0) {
        g_checksum_update(checksum, (guchar *)tmpBuf, BSB_LENGTH(tmpBSB));
        memcpy(ja4 + 13, g_checksum_get_string(checksum), 12);
        g_checksum_reset(checksum);
    } else {
        memcpy(ja4 + 13, "000000000000", 12);
    }

    arkime_field_string_add(ja4sField, session, ja4, 25, TRUE);
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
    ArkimeCertsInfo_t *info = uw;

    uint32_t atag, alen, apc;
    uint8_t *value;

    BSB      bsb;
    BSB_INIT(bsb, data, len);

    /* Certificate */
    if (!(value = arkime_parsers_asn_get_tlv(&bsb, &apc, &atag, &alen)))
    {
        goto bad_cert;
    }
    BSB_INIT(bsb, value, alen);

    /* signedCertificate */
    if (!(value = arkime_parsers_asn_get_tlv(&bsb, &apc, &atag, &alen)))
    {
        goto bad_cert;
    }
    BSB_INIT(bsb, value, alen);

    /* serialNumber or version*/
    if (!(value = arkime_parsers_asn_get_tlv(&bsb, &apc, &atag, &alen)))
    {
        goto bad_cert;
    }

    if (apc) {
        if (!(value = arkime_parsers_asn_get_tlv(&bsb, &apc, &atag, &alen)))
        {
            goto bad_cert;
        }
    }

    /* signature */
    if (!arkime_parsers_asn_get_tlv(&bsb, &apc, &atag, &alen))
    {
        goto bad_cert;
    }

    /* issuer */
    if (!(value = arkime_parsers_asn_get_tlv(&bsb, &apc, &atag, &alen)))
    {
        goto bad_cert;
    }
    BSB out;
    char outbuf[1000];
    char ja4x[39];
    ja4x[12] = ja4x[25] = '_';
    ja4x[38] = 0;

    BSB tbsb;
    BSB_INIT(tbsb, value, alen);

    BSB_INIT(out, outbuf, sizeof(outbuf));
    ja4plus_cert_process_rdn(&tbsb, &out);
    ja4plus_cert_print(session->thread, 0,  ja4x, &out);

    /* validity */
    if (!(value = arkime_parsers_asn_get_tlv(&bsb, &apc, &atag, &alen)))
    {
        goto bad_cert;
    }

    BSB_INIT(tbsb, value, alen);
    if (!(value = arkime_parsers_asn_get_tlv(&tbsb, &apc, &atag, &alen)))
    {
        goto bad_cert;
    }

    if (!(value = arkime_parsers_asn_get_tlv(&tbsb, &apc, &atag, &alen)))
    {
        goto bad_cert;
    }

    /* subject */
    if (!(value = arkime_parsers_asn_get_tlv(&bsb, &apc, &atag, &alen)))
    {
        goto bad_cert;
    }
    BSB_INIT(tbsb, value, alen);
    BSB_INIT(out, outbuf, sizeof(outbuf));
    ja4plus_cert_process_rdn(&tbsb, &out);
    ja4plus_cert_print(session->thread, 1, ja4x, &out);

    /* subjectPublicKeyInfo */
    if (!(value = arkime_parsers_asn_get_tlv(&bsb, &apc, &atag, &alen)))
    {
        goto bad_cert;
    }

    /* extensions */
    BSB_INIT(out, outbuf, sizeof(outbuf));
    ja4plus_cert_process_rdn(&bsb, &out);
    ja4plus_cert_print(session->thread, 2, ja4x, &out);

    arkime_field_certsinfo_update_extra(info, g_strdup("ja4x"), g_strdup(ja4x));
    return 0;

bad_cert:
    return 0;
}
/******************************************************************************/
LOCAL uint32_t ja4plus_ssh_ja4ssh(ArkimeSession_t *session, const uint8_t *UNUSED(data), int UNUSED(len), void *uw)
{
    // https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4SSH.md
    char ja4ssh[50];
    BSB bsb;

    SSHJA4_t *sshja4 = uw;

    BSB_INIT(bsb, ja4ssh, sizeof(ja4ssh));
    BSB_EXPORT_sprintf(bsb, "c%ds%d_c%ds%d_c%ds%d",
                       sshja4->modes[0], sshja4->modes[1],
                       sshja4->packets[0], sshja4->packets[1],
                       session->tcpFlagAckCnt[0], session->tcpFlagAckCnt[1]);

    arkime_field_string_add(ja4sshField, session, ja4ssh, BSB_LENGTH(bsb), TRUE);
    return 0;
}
/******************************************************************************/
void arkime_plugin_init()
{
    arkime_parser_add_named_func("tls_process_server_hello", ja4plus_process_server_hello);
    arkime_parser_add_named_func("tls_process_certificate_wInfo", ja4plus_process_certificate_wInfo);
    arkime_parser_add_named_func("ssh_ja4ssh", ja4plus_ssh_ja4ssh);

    ja4sField = arkime_field_define("tls", "lotermfield",
                                    "tls.ja4s", "JA4s", "tls.ja4s",
                                    "SSL/TLS JA4s field",
                                    ARKIME_FIELD_TYPE_STR_GHASH,  ARKIME_FIELD_FLAG_CNT,
                                    (char *)NULL);


    arkime_field_define("cert", "termfield",
                        "cert.ja4x", "JA4x", "cert.ja4x",
                        "JA4x",
                        0, ARKIME_FIELD_FLAG_FAKE,
                        (char *)NULL);

    ja4sshField = arkime_field_define("ssh", "lotermfield",
                                      "ssh.ja4ssh", "JA4ssh", "ssh.ja4ssh",
                                      "SSH JA4ssh field",
                                      ARKIME_FIELD_TYPE_STR_GHASH,  ARKIME_FIELD_FLAG_CNT,
                                      (char *)NULL);

    int t;
    for (t = 0; t < config.packetThreads; t++) {
        checksums256[t] = g_checksum_new(G_CHECKSUM_SHA256);
    }
}
