/*
 * This file is part of the Micro Python project, http://micropython.org/
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 Paul Sokolovsky
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "py/nlr.h"
#include "py/objlist.h"
#include "py/runtime.h"
#include "py/mphal.h"
#include "netutils.h"
#include "queue.h"
#include "user_interface.h"
#include "espconn.h"
#include "spi_flash.h"
#include "ets_alt_task.h"
#include "lwip/dns.h"


// Headers from ESP8266 technical reference manual, section 14.1
struct RxControl {
    signed rssi:8; // signal intensity of packet
    unsigned rate:4;
    unsigned is_group:1;
    unsigned:1;
    unsigned sig_mode:2; // 0:is not 11n packet; non-0:is 11n packet;
    unsigned legacy_length:12; // if not 11n packet, shows length of packet.
    unsigned damatch0:1;
    unsigned damatch1:1;
  
    unsigned bssidmatch0:1;
    unsigned bssidmatch1:1;
    unsigned MCS:7; // if is 11n packet, shows the modulation and code used (range from 0 to 76)
    unsigned CWB:1; // if is 11n packet, shows if is HT40 packet or not
    unsigned HT_length:16;// if is 11n packet, shows length of packet.
    unsigned Smoothing:1;
    unsigned Not_Sounding:1;
    unsigned:1;
    unsigned Aggregation:1;
    unsigned STBC:2;
    unsigned FEC_CODING:1; // if is 11n packet, shows if is LDPC packet or not.
    unsigned SGI:1;
    unsigned rxend_state:8;
    unsigned ampdu_cnt:8;
    unsigned channel:4; //which channel this packet in.
    unsigned:12;
};

struct LenSeq {
    u16 len; // length of packet
    u16 seq; // serial number of packet, the high 12bits are serial number,
             // low 14 bits are Fragment number (usually be 0)
    u8 addr3[6]; // the third address in packet
};

struct sniffer_buf {
    struct RxControl rx_ctrl;
    u8 buf[36]; // head of ieee80211 packet
    u16 cnt; // number count of packet
    struct LenSeq lenseq[1]; //length of packet 
};

struct sniffer_buf2 {
    struct RxControl rx_ctrl;
    u8 buf[112]; //may be 240, please refer to the real source code
    u16 cnt;
    u16 len; //length of packet
}; 

#define NUM_DICT_ENTRIES 6

/* 
 * Dictionary definition:
 *
 * rssi: rx->rssi
 * pktlen: rx->legacy_length or HT_length, depending on whether 11n or not
 * channel: rx->channel
 * mcs: rx->MCS
 * data: raw header data from packet
 * datalen: (Not really needed? Is this encoded as part of the byte array data)
 */

mp_obj_t esp_parse_sniffer_rx(uint8* buf, uint16 len)
{
    mp_obj_t dict = mp_obj_new_dict(NUM_DICT_ENTRIES);

    dict=dict;
    struct RxControl *rx_ctrl = (struct RxControl *) buf;

    mp_obj_dict_store(dict, MP_OBJ_NEW_QSTR(MP_QSTR_rssi), MP_OBJ_NEW_SMALL_INT(rx_ctrl->rssi));

    uint16_t pktlen = rx_ctrl->sig_mode > 0 ? rx_ctrl->HT_length : rx_ctrl->legacy_length;
    
    mp_obj_dict_store(dict, MP_OBJ_NEW_QSTR(MP_QSTR_pktlen), MP_OBJ_NEW_SMALL_INT(pktlen));


    mp_obj_t data;
	
    if (len == sizeof(struct sniffer_buf)) {
	data = mp_obj_new_bytes( ((struct sniffer_buf *) buf)->buf, 36);
    }
    else if (len == sizeof(struct sniffer_buf2)) {
	data = mp_obj_new_bytes( ((struct sniffer_buf2 *) buf)->buf, 112);
    }
    else {
	return mp_const_none;
    }

    mp_obj_dict_store(dict, MP_OBJ_NEW_QSTR(MP_QSTR_data), data);
    mp_obj_dict_store(dict, MP_OBJ_NEW_QSTR(MP_QSTR_datalen), MP_OBJ_NEW_SMALL_INT(len));

    return dict;

}
