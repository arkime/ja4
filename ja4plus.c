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
#include "../parsers/ssh_info.h"

typedef struct {
    ArkimeSession_t *session;
    GString         *urlString;
    GString         *hostString;
    GString         *cookieString;
    GString         *authString;
    GString         *proxyAuthString;

    GString         *valueString[2];

    char             header[2][40];
    short            pos[2];
    http_parser     parsers[2];
} http_t;

typedef struct {
    // Used for JA4L
    struct timeval timestampA;
    struct timeval timestampB;
    struct timeval timestampC;
    struct timeval timestampD;
    struct timeval timestampE;
    struct timeval timestampF;
    struct timeval synAckTimes[10];
    int syn_ack_count;
    int client_ttl;
    int server_ttl;

    // Used for JA4H
    int cookies;
    int referer;
    int headers;
    GString *accept_lang;
    GString *header_fields;
    gchar *cookie_fields;
    gchar *cookie_values;
    gchar *sorted_cookie_fields;
    gchar *sorted_cookie_values;
    char state;
} ja4plus_data_t;

extern ArkimeConfig_t        config;
int 			     ja4plugin_num;
LOCAL int                    ja4sField;
LOCAL int                    ja4sRawField;
LOCAL int                    ja4sshField;
LOCAL int                    ja4hField;
LOCAL int                    ja4hRawField;
LOCAL int                    ja4hRawOriginalField;
LOCAL int                    ja4tcField;
LOCAL int                    ja4tsField;
LOCAL int                    ja4lcField;
LOCAL int                    ja4lsField;
LOCAL GChecksum             *checksums256[ARKIME_MAX_PACKET_THREADS];
extern uint8_t               arkime_char_to_hexstr[256][3];

/******************************************************************************/

LOCAL int ja4plus_timediff(struct timeval t1, struct timeval t2) 
{
    return (t2.tv_sec - t1.tv_sec) * 1000 + (t2.tv_usec - t1.tv_usec);
}

// Gstring needs to be freed by the caller.
LOCAL GString *ja4plus_syn_ack_diffs(struct timeval *tvs, int count) 
{
    GString *time_diffs = g_string_new_len("", 0);
    for (int i=1; i<count; i++) {
	g_string_append_printf(time_diffs, "%d", ja4plus_timediff(tvs[i-1], tvs[i]));
	if (i != (count-1))
	    g_string_append_printf(time_diffs, "%c", '-');
    }
    return time_diffs;
}

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

LOCAL int cstring_cmp(const void *a, const void *b)
{
    return strcmp(*(char **)a, *(char **)b);
}

LOCAL gchar *get_cookie_fields(gchar *s)
{
    char **kv = g_strsplit(s, ",", 0);
    char *keys[200];
    int i = 0;

    for (i=0; kv[i]; i++) {
	char **temp = g_strsplit(kv[i], "=", 0);
	keys[i] = temp[0];
    }
    keys[i] = '\0';

    char *ret = g_strjoinv(",",keys);
    g_free(kv);
    return ret;
}

/*
 * Getting accept language can be tricky, we need to 
 * take care of all the following
 * en-US,en;q=0.9
 * en-US\r\n
 * de, en-US;xxxx
 * The easiest way is not to split by ":" but to search for a hyphen 
 * and use the 2 preceeding and succeeding characters
 */
LOCAL void get_accept_language(char *out, const char *s) 
{
    char **lines = g_strsplit(s, "\r\n", 0);
    if (lines[0]) {
	char *lang = g_ascii_strdown(lines[0], strlen(lines[0]));
	unsigned int i = 0;
	for (i=0; i < strlen(lang); i++) {
	    if ((lang[i] == '-')  && (out)) {
		out[0] = lang[i-2];
		out[1] = lang[i-1];
		out[2] = lang[i+1];
		out[3] = lang[i+2];
		return;
	    }
	}
    }
}

/*
 * This records the JA4TS fingerprint
 */
LOCAL void ja4plus_ja4ts(ArkimeSession_t *session, ja4plus_data_t *data, struct tcphdr *tcph)
{
    // Skip to the options part
    uint8_t *p = (uint8_t *)tcph + 20;
    uint8_t *end = (uint8_t *)tcph + tcph->doff * 4;
    uint16_t mss = 0;
    uint8_t window_scale = 0;
    GString *ja4ts = g_string_new_len("", 0);
    g_string_append_printf(ja4ts, "%d_", tcph->th_win);
    while (p < end) {
        uint8_t next = *p++;
        g_string_append_printf(ja4ts, "%02d", next);
        if (next == 1)
            continue;
        uint8_t size = *p++;
        if (next == 2)
            mss = ntohs(*(uint16_t *)p);
        if (next == 3)
            window_scale = *p;
        p += (size - 2);
    }

    g_string_append_printf(ja4ts, "_%d_%d", mss, window_scale);
    if (data->syn_ack_count > 1) {
        GString *syn_ack_diffs = ja4plus_syn_ack_diffs(data->synAckTimes, data->syn_ack_count);
        g_string_append_printf(ja4ts, "_%s", syn_ack_diffs->str);
        if (syn_ack_diffs != NULL) 
            g_free(syn_ack_diffs);
    }
    //printf("-----JA4TS--- %s\n", ja4ts->str);
    arkime_field_string_add(ja4tsField, session, ja4ts->str, strlen(ja4ts->str), TRUE);
}

/*
 * This records the JA4TC fingerprint
 */
LOCAL void ja4plus_ja4tc(ArkimeSession_t *session, ja4plus_data_t UNUSED(*data), struct tcphdr *tcph)
{
    // Skip to the options part
    uint8_t *p = (uint8_t *)tcph + 20;
    uint8_t *end = (uint8_t *)tcph + tcph->doff * 4;
    uint16_t mss = 0;
    uint8_t window_scale = 0;
    GString *ja4tc = g_string_new_len("", 0);
    g_string_append_printf(ja4tc, "%d_", tcph->th_win);
    while (p < end) {
        uint8_t next = *p++;
        g_string_append_printf(ja4tc, "%02d", next);
        if (next == 1)
            continue;
        uint8_t size = *p++;
        if (next == 2)
            mss = ntohs(*(uint16_t *)p);
        if (next == 3)
            window_scale = *p;
        p += (size - 2);
    }
    g_string_append_printf(ja4tc, "_%d_%d", mss, window_scale);
    arkime_field_string_add(ja4tcField, session, ja4tc->str, strlen(ja4tc->str), TRUE);
}
/******************************************************************************/

/************* JA4H *************************************/
LOCAL void ja4plus_http_process(ArkimeSession_t *session, int UNUSED(final)) 
{
    if (arkime_session_has_protocol(session, "http")) {
	char ja4h[512] = {0};
	char ja4h_r[512] = {0};
	char ja4h_ro[512] = {0};
	http_t *http = session->parserInfo->uw;
	http_parser *parser = (http_parser *) &http->parsers[0];
	char *method = g_ascii_strdown(http_method_str(parser->method), 2);
	ja4plus_data_t *ja4h_data = (ja4plus_data_t *) session->pluginData[ja4plugin_num];

	if (ja4h_data && ja4h_data->header_fields && parser && (parser->type == 0)) {
    	    GChecksum *const checksum = checksums256[session->thread];
	    snprintf(ja4h, 20, "%s%d%d%c%c%02d%s_",  
		method, 
		parser->http_major, 
		parser->http_minor,
		(ja4h_data->cookies == 0) ? 'n' : 'c',
		(ja4h_data->referer == 0) ? 'n' : 'r',
		ja4h_data->headers,
		ja4h_data->accept_lang ? ja4h_data->accept_lang->str : "0000"
	    );

	    g_checksum_update(checksum, (guchar *)ja4h_data->header_fields->str, ja4h_data->header_fields->len);
	    memcpy(ja4h+13, g_checksum_get_string(checksum), 12);
       	    g_checksum_reset(checksum);
	    ja4h[25] = '_';

	    if (ja4h_data->cookies) {
		g_checksum_update(checksum, (guchar *) ja4h_data->sorted_cookie_fields, strlen(ja4h_data->sorted_cookie_fields));
		memcpy(ja4h+26, g_checksum_get_string(checksum), 12);
       		g_checksum_reset(checksum);
		ja4h[37] = '_';

		g_checksum_update(checksum, (guchar *) ja4h_data->sorted_cookie_values, strlen(ja4h_data->sorted_cookie_values));
		memcpy(ja4h+38, g_checksum_get_string(checksum), 12);
       		g_checksum_reset(checksum);
	    } else {
		g_strlcpy(ja4h+26, "000000000000_000000000000", 25);
    	    }
	    //printf("%s\n", ja4h);
    	    arkime_field_string_add(ja4hField, session, ja4h, strlen(ja4h), TRUE);

	    snprintf(ja4h_r, 512, "%s%d%d%c%c%02d%s_%s_%s_%s", 
		method, 
		parser->http_major, 
		parser->http_minor,
		(ja4h_data->cookies == 0) ? 'n' : 'c',
		(ja4h_data->referer == 0) ? 'n' : 'r',
		ja4h_data->headers,
		ja4h_data->accept_lang ? ja4h_data->accept_lang->str : "0000",
		ja4h_data->header_fields->str,
		(ja4h_data->sorted_cookie_fields != NULL) ? ja4h_data->sorted_cookie_fields : "",
		(ja4h_data->sorted_cookie_values != NULL) ? ja4h_data->sorted_cookie_values : ""
	    );
	    //printf("%s\n", ja4h_r);
    	    arkime_field_string_add(ja4hRawField, session, ja4h_r, strlen(ja4h_r), TRUE);

	    snprintf(ja4h_ro, 512, "%s%d%d%c%c%02d%s_%s_%s_%s", 
		method, 
		parser->http_major, 
		parser->http_minor,
		(ja4h_data->cookies == 0) ? 'n' : 'c',
		(ja4h_data->referer == 0) ? 'n' : 'r',
		ja4h_data->headers,
		ja4h_data->accept_lang ? ja4h_data->accept_lang->str : "0000",
		ja4h_data->header_fields->str,
		(ja4h_data->cookie_fields != NULL) ? ja4h_data->cookie_fields : "",
		(ja4h_data->cookie_values != NULL) ? ja4h_data->cookie_values : ""
	    );
	    //printf("%s\n", ja4h_ro);
    	    arkime_field_string_add(ja4hRawOriginalField, session, ja4h_ro, strlen(ja4h_ro), TRUE);
	}
    }
}

LOCAL void ja4plus_http_header_field_raw (ArkimeSession_t *session, http_parser *hp, const char *at, size_t UNUSED(length))
{
    char comma = ',';
    if (at && (hp->type == 0)) {
	ja4plus_data_t *ja4h_data = session->pluginData[ja4plugin_num];
	if (!ja4h_data) {
	    ja4h_data = session->pluginData[ja4plugin_num] = ARKIME_TYPE_ALLOC0 (ja4plus_data_t);
	    ja4h_data->cookies = 0;
	    ja4h_data->header_fields = g_string_new_len(at, strlen(at));
	    ja4h_data->headers = 1;
	    ja4h_data->state = 'o';
	    ja4h_data->accept_lang = g_string_new_len("0000", 4);
	    /*ja4h_data->accept_lang[0] = '0';
	    ja4h_data->accept_lang[1] = '0';
	    ja4h_data->accept_lang[2] = '0';
	    ja4h_data->accept_lang[3] = '0';
	    ja4h_data->accept_lang[4] = '\0';*/
	} else {
	    char *header_field = g_ascii_strdown(at, strlen(at));
    	    if (strcmp(header_field, "cookie") == 0) {
		ja4h_data->state = 'c';
	    } else if (strcmp(header_field, "referer") == 0) {
		ja4h_data->referer = 1;
		ja4h_data->state = 'r';
	    } else {
		ja4h_data->headers++;
		g_string_append_len(ja4h_data->header_fields, &comma, 1);
		g_string_append_len(ja4h_data->header_fields, at, strlen(at));
		if (strcmp(header_field, "accept-language") == 0) {
			ja4h_data->state = 'a';
		} else {
			ja4h_data->state = 'o';
		}
	    }
	}
    }
}

LOCAL void ja4plus_http_header_value (ArkimeSession_t *session, http_parser *hp, const char *at, size_t UNUSED(length))
{
    if (at && (hp->type == 0)) {
	ja4plus_data_t *ja4h_data = session->pluginData[ja4plugin_num];
	if (ja4h_data->state == 'c') {
	    char **lines = g_strsplit(at, "\r\n", 0);
	    if (lines[0]) {
		char **vals = g_strsplit(lines[0], ";", 0);

		// Cleanup cookie key value pairs by removing 
		// leading and trailing spaces
		for (int k=0; vals[k]; k++) {
			g_strstrip(vals[k]);
			ja4h_data->cookies++;
		}

		ja4h_data->cookie_values = g_strjoinv(",", vals);
		qsort((void *)vals, (size_t)ja4h_data->cookies, sizeof(char *), cstring_cmp);
		ja4h_data->sorted_cookie_values = g_strjoinv(",", vals);
		ja4h_data->cookie_fields = get_cookie_fields(ja4h_data->cookie_values);
		ja4h_data->sorted_cookie_fields = get_cookie_fields(ja4h_data->sorted_cookie_values);
		g_free(vals);
	    }
	    g_free(lines);
	} 
	if (ja4h_data->state == 'a')
	    get_accept_language(ja4h_data->accept_lang->str, at);
    }
}
/************* END of JA4H *************************************/

/************* JA4L *************************************/
LOCAL void ja4plus_tcp_process(ArkimeSession_t *session, const uint8_t *data, int len, int which) {
    ja4plus_data_t *ja4plus_data = session->pluginData[ja4plugin_num];
    if (!ja4plus_data) {
	ja4plus_data = session->pluginData[ja4plugin_num] = ARKIME_TYPE_ALLOC0 (ja4plus_data_t);
	ja4plus_data->header_fields = g_string_new_len("", 0);
    }

    if (len == 0) {
	ArkimePacket_t *packet = (ArkimePacket_t *)data;
	struct tcphdr *tcp = (struct tcphdr *) (packet->pkt + packet->payloadOffset);
	struct ip *ip4 = (struct ip *) (packet->pkt + packet->ipOffset);

	if (tcp->th_flags & TH_SYN) {
    	    if (tcp->th_flags & TH_ACK) {
		ja4plus_data->timestampB = packet->ts;
		ja4plus_data->server_ttl = ip4->ip_ttl;
		ja4plus_data->syn_ack_count = session->tcpFlagCnt[ARKIME_TCPFLAG_SYN_ACK];
		if (session->tcpFlagCnt[ARKIME_TCPFLAG_SYN_ACK] < 10) {
			ja4plus_data->synAckTimes[session->tcpFlagCnt[ARKIME_TCPFLAG_SYN_ACK]-1] = packet->ts;
		}
		ja4plus_ja4ts(session, ja4plus_data, tcp);
	    } else {
		ja4plus_data->client_ttl = ip4->ip_ttl;
		ja4plus_data->timestampA = packet->ts;
		ja4plus_ja4tc(session, ja4plus_data, tcp);
	    }
        } else {
	    if ((tcp->th_flags & TH_ACK) && (ja4plus_data->timestampC.tv_sec ==0))
		ja4plus_data->timestampC = packet->ts;
        }
    } else {
	if (which == 0) { 
	    if (ja4plus_data->timestampD.tv_sec == 0) {
		// First client packet
		ja4plus_data->timestampD = session->lastPacket;
	    } else {
		// second client packet, provided server sent out its packet
		if ((ja4plus_data->timestampE.tv_sec != 0) && (ja4plus_data->timestampF.tv_sec == 0)) {
	    	    GString *ja4lc = g_string_new_len("", 0);
		    ja4plus_data->timestampF = session->lastPacket;
		    g_string_append_printf(ja4lc, "%d_%d_%d", 
			ja4plus_timediff(ja4plus_data->timestampB, ja4plus_data->timestampC) / 2,
			ja4plus_data->client_ttl,
			ja4plus_timediff(ja4plus_data->timestampE, ja4plus_data->timestampF) / 2
		    );
		    //printf("----JA4LC---%s\n", ja4lc->str);
                    arkime_field_string_add(ja4lcField, session, ja4lc->str, strlen(ja4lc->str), TRUE);
		}
	    }
	}

	if ((which == 1) && (ja4plus_data->timestampE.tv_sec == 0)) {
	    GString *ja4ls = g_string_new_len("", 0);
	    ja4plus_data->timestampE = session->lastPacket;
	    g_string_append_printf(ja4ls, "%d_%d_%d", 
		ja4plus_timediff(ja4plus_data->timestampA, ja4plus_data->timestampB) / 2,
		ja4plus_data->server_ttl,
		ja4plus_timediff(ja4plus_data->timestampD, ja4plus_data->timestampE) / 2
	    );
	    //printf("----JA4LS---%s\n", ja4ls->str);
            arkime_field_string_add(ja4lsField, session, ja4ls->str, strlen(ja4ls->str), TRUE);
	}
    }
}

/* End of JA4L */

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
    char ja4s_r[255] = {0};
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

    memcpy(ja4s_r, ja4, 13);
    memcpy(ja4s_r + 13, tmpBuf, BSB_LENGTH(tmpBSB));

    //printf("----JA4S-----[ %s ]\n", ja4);
    //printf("----JA4s_r-----[ %s ]\n", ja4s_r);
    arkime_field_string_add(ja4sField, session, ja4, 25, TRUE);
    arkime_field_string_add(ja4sRawField, session, ja4s_r, 254, TRUE);
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
    char ja4x_r[255] = {0};
    char *raw_pointer = ja4x_r;

    ja4x[12] = ja4x[25] = '_';
    ja4x[38] = 0;

    BSB tbsb;
    BSB_INIT(tbsb, value, alen);

    BSB_INIT(out, outbuf, sizeof(outbuf));
    ja4plus_cert_process_rdn(&tbsb, &out);

    memcpy(raw_pointer, out.buf, BSB_LENGTH(out)-1);
    raw_pointer += (BSB_LENGTH(out) - 1);
    memcpy(raw_pointer, "_", 1);
    raw_pointer ++;

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

    memcpy(raw_pointer, out.buf, BSB_LENGTH(out)-1);
    raw_pointer += (BSB_LENGTH(out) - 1);
    memcpy(raw_pointer, "_", 1);
    raw_pointer ++;

    ja4plus_cert_print(session->thread, 1, ja4x, &out);

    /* subjectPublicKeyInfo */
    if (!(value = arkime_parsers_asn_get_tlv(&bsb, &apc, &atag, &alen)))
    {
        goto bad_cert;
    }

    /* extensions */
    BSB_INIT(out, outbuf, sizeof(outbuf));
    ja4plus_cert_process_rdn(&bsb, &out);

    memcpy(raw_pointer, out.buf, BSB_LENGTH(out)-1);
    ja4plus_cert_print(session->thread, 2, ja4x, &out);

    arkime_field_certsinfo_update_extra(info, g_strdup("ja4x"), g_strdup(ja4x));
    arkime_field_certsinfo_update_extra(info, g_strdup("ja4x_r"), g_strdup(ja4x_r));
    return 0;

bad_cert:
    return 0;
}
/******************************************************************************/
// Given a list of numbers find the mode, we ignore numbers > 2048
LOCAL int ja4plus_ssh_mode(uint16_t *nums, int num) {
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

    SSHInfo_t *ssh = uw;

    BSB_INIT(bsb, ja4ssh, sizeof(ja4ssh));
    BSB_EXPORT_sprintf(bsb, "c%ds%d_c%ds%d_c%ds%d",
                       ja4plus_ssh_mode(ssh->lens[0], ssh->packets[0]), ja4plus_ssh_mode(ssh->lens[1], ssh->packets[1]),
                       ssh->packets[0], ssh->packets[1],
                       session->tcpFlagAckCnt[0], session->tcpFlagAckCnt[1]);

    //printf("----JA4SSH-----[ %s ]\n", ja4ssh);
    arkime_field_string_add(ja4sshField, session, ja4ssh, BSB_LENGTH(bsb), TRUE);
    return 0;
}

/******************************************************************************/


void arkime_plugin_init()
{

    ja4plugin_num = arkime_plugins_register("ja4plus", TRUE);

    arkime_plugins_set_cb("ja4plus",
                          NULL,
                          NULL,
                          ja4plus_tcp_process,
                          NULL,
                          ja4plus_http_process,
                          //NULL,
                          NULL,
                          NULL,
                          NULL
                         );

    arkime_plugins_set_http_ext_cb("ja4plus",
		    NULL,
		    NULL,
		    NULL,
		    ja4plus_http_header_field_raw,
		    ja4plus_http_header_value,
		    NULL,
		    NULL,
		    NULL);

    arkime_parser_add_named_func("tls_process_server_hello", ja4plus_process_server_hello);
    arkime_parser_add_named_func("tls_process_certificate_wInfo", ja4plus_process_certificate_wInfo);
    arkime_parser_add_named_func("ssh_counting200", ja4plus_ssh_ja4ssh);

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

    ja4hRawOriginalField = arkime_field_define("http", "lotermfield",
                                      "http.ja4h_ro", "JA4h_ro", "http.ja4h_ro",
                                      "HTTP JA4h Raw Original field",
                                      ARKIME_FIELD_TYPE_STR_GHASH,  ARKIME_FIELD_FLAG_CNT,
                                      (char *)NULL);

    ja4lcField = arkime_field_define("tcp", "lotermfield",
                                      "tcp.ja4lc", "JA4lc", "tcp.ja4lc",
                                      "JA4 Latency Client field",
                                      ARKIME_FIELD_TYPE_STR_GHASH,  ARKIME_FIELD_FLAG_CNT,
                                      (char *)NULL);

    ja4lsField = arkime_field_define("tcp", "lotermfield",
                                      "tcp.ja4ls", "JA4ls", "tcp.ja4ls",
                                      "JA4 Latency Server field",
                                      ARKIME_FIELD_TYPE_STR_GHASH,  ARKIME_FIELD_FLAG_CNT,
                                      (char *)NULL);

    ja4tsField = arkime_field_define("tcp", "lotermfield",
                                      "tcp.ja4ts", "JA4ts", "tcp.ja4ts",
                                      "JA4 TCP Server field",
                                      ARKIME_FIELD_TYPE_STR_GHASH,  ARKIME_FIELD_FLAG_CNT,
                                      (char *)NULL);

    ja4tcField = arkime_field_define("tcp", "lotermfield",
                                      "tcp.ja4tc", "JA4tc", "tcp.ja4tc",
                                      "JA4 TCP Client field",
                                      ARKIME_FIELD_TYPE_STR_GHASH,  ARKIME_FIELD_FLAG_CNT,
                                      (char *)NULL);

    arkime_field_define("cert", "termfield",
                        "cert.ja4x", "JA4x", "cert.ja4x",
                        "JA4x",
                        0, ARKIME_FIELD_FLAG_FAKE,
                        (char *)NULL);

    arkime_field_define("cert", "termfield",
                        "cert.ja4x_r", "JA4x_r", "cert.ja4x_r",
                        "JA4x_r",
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
