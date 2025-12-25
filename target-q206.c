// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * target-q206.c - tama X_BOOT_SDM845_LA2_0_Q_206 bootloader target specifics
 *
 * Copyright (C) 2025 j4nn at xdaforums
 */

static const int q206_offset = 0x2a7000; //0x3f7030; //0x400000; //incorrect
static const int q206_size   = 0x400f90; //0x3fc030; //0x408000;

static const int64_t q206_test3_hitadj = -0x97ffebeeLL + 0x3a494LL - 4LL;
static const int q206_stage1_cont = 0x3a438;
static const char q206_test4_cmd[] = "flash:fb";


static void q206_setup_test2(unsigned char *buff, int size, int offset)
{
    int i;

    for (i = (offset % 0x80); i < size; i += 0x80) {
        OPCODE(buff + i + 0x00, 0x01, 0x00, 0x00, 0x94);        // bl     #0x04 = [ 01 00 00 94 ]
        OPCODE(buff + i + 0x04, 0xe2, 0xff, 0xff, 0x10);        // adr    x2, #-0x04 = [ e2 ff ff 10 ]
        OPCODE(buff + i + 0x08, 0xc2, 0x03, 0x02, 0xcb);        // sub    x2, lr, x2 = [ c2 03 02 cb ]
        OPCODE(buff + i + 0x0c, 0x02, 0x00, 0x00, 0x14);        // b      #0x08 = [ 02 00 00 14 ]

        OPCODE(buff + i + 0x10, 0xfd, 0xff, 0xff, 0x97);        // bl     #-0x0c = [ fd ff ff 97 ]
        OPCODE(buff + i + 0x14, 0xe0, 0xff, 0xb2, 0xd2);        // movz   x0, #0x97ff, lsl #16 = [ e0 ff b2 d2 ]    code "EE EB FF 97" is a call to return
        OPCODE(buff + i + 0x18, 0xc0, 0x7d, 0x9d, 0xf2);        // movk   x0, #0xebee = [ c0 7d 9d f2 ]             fastboot FAIL response - search for it
        OPCODE(buff + i + 0x1c, 0x02, 0x00, 0x00, 0x14);        // b      #0x08 = [ 02 00 00 14 ]

        OPCODE(buff + i + 0x20, 0xf9, 0xff, 0xff, 0x97);        // bl     #-0x1c = [ f9 ff ff 97 ]
        OPCODE(buff + i + 0x24, 0xfe, 0xff, 0xff, 0xf0);        // adrp   lr, #-0x1000 = [ fe ff ff f0 ]
        OPCODE(buff + i + 0x28, 0xc1, 0x47, 0x40, 0xb8);        // ldr    w1, [lr], #4 = [ c1 47 40 b8 ]
        OPCODE(buff + i + 0x2c, 0x02, 0x00, 0x00, 0x14);        // b      #0x08 = [ 02 00 00 14 ]

        OPCODE(buff + i + 0x30, 0xf5, 0xff, 0xff, 0x97);        // bl     #-0x2c = [ f5 ff ff 97 ]
        OPCODE(buff + i + 0x34, 0x3f, 0x00, 0x00, 0x6b);        // cmp    w1, w0 = [ 3f 00 00 6b ]
        OPCODE(buff + i + 0x38, 0x81, 0xff, 0xff, 0x54);        // b.ne   #-0x10 = [ 81 ff ff 54 ]                  lr = 0x3a494, i.e. addr of code after
        OPCODE(buff + i + 0x3c, 0x06, 0x00, 0x00, 0x14);        // b      #0x18 = [ 06 00 00 14 ]                   the call to return fb FAIL response

        OPCODE(buff + i + 0x40, 0xf1, 0xff, 0xff, 0x97);        // bl     #-0x3c = [ f1 ff ff 97 ]
        snprintf(buff + i + 0x44, 5+7, "vxyz%06x-", i);         // "f3ce40-e40-" "vxyzf3ce40-"

        OPCODE(buff + i + 0x50, 0xed, 0xff, 0xff, 0x97);        // bl     #-0x4c = [ ed ff ff 97 ]
        OPCODE(buff + i + 0x54, 0xa0, 0xff, 0xff, 0x10);        // adr    x0, #-0x0c = [ a0 ff ff 10 ]
        OPCODE(buff + i + 0x58, 0x61, 0xff, 0xff, 0x10);        // adr    x1, #-0x14 = [ 61 ff ff 10 ]
        OPCODE(buff + i + 0x5c, 0x02, 0x00, 0x00, 0x14);        // b      #0x08 = [ 02 00 00 14 ]

        OPCODE(buff + i + 0x60, 0xe9, 0xff, 0xff, 0x97);        // bl     #-0x5c = [ e9 ff ff 97 ]
        OPCODE(buff + i + 0x64, 0x42, 0xfc, 0x44, 0xd3);        // lsr    x2, x2, #4 = [ 42 fc 44 d3 ]
        OPCODE(buff + i + 0x68, 0x21, 0x00, 0x02, 0x8b);        // add    x1, x1, x2 = [ 21 00 02 8b ]
        OPCODE(buff + i + 0x6c, 0x02, 0x00, 0x00, 0x14);        // b      #0x08 = [ 02 00 00 14 ]

        OPCODE(buff + i + 0x70, 0xe5, 0xff, 0xff, 0x97);        // bl     #-0x6c = [ e5 ff ff 97 ]
        OPCODE(buff + i + 0x74, 0x94, 0x00, 0x8a, 0xd2);        // movz   x20, #0x5004 = [ 94 00 8A D2 ]
        OPCODE(buff + i + 0x78, 0xd4, 0x03, 0x14, 0xcb);        // sub    x20, lr, x20 = [ d4 03 14 cb ]            x20 points to code to return our fb
        OPCODE(buff + i + 0x7c, 0x80, 0x02, 0x1f, 0xd6);        // br     x20 = [ 80 02 1f d6 ]                     response - link back to 0x3a494
    }
}

static void q206_setup_test3(unsigned char *buff, int size, int offset)
{
    int i, j;

    memset(buff, 0, size);
    if (offset < 0)
        offset = size - 0x4000;

    *(uint64_t *)(buff + 0x1000) = 0x97ffebeeULL | (0x97ffebeeULL << 32); // code "EE EB FF 97" at 0x322D8 to return fastboot fail response
    *(uint64_t *)(buff + 0x1008) = 0x000fb000;                  // code boundary of LinuxLoader-q206.pe is 0x000fb000
    *(uint64_t *)(buff + 0x1010) = 0x0003a494;                  // address of code to return fastboot FAIL response
    *(uint64_t *)(buff + 0x1018) = 0x0011e1f8;                  // address of download mode usb buffer pointer

    int bs = 0x100;

    for (i = offset; i < size; i += bs) {
        snprintf(buff + (0x2000 + i / bs * 16), 8, "%06x:", i);

        OPCODE(buff + i + 0x00, 0x03, 0x00, 0x00, 0x10);        // adr    x3, #0x00 = [ 03 00 00 10 ]
        OPCODE(buff + i + 0x04, 0x61, 0x10, 0x43, 0x29);        // ldp    w1, w4, [x3, #0x18] = [ 61 10 43 29 ]     w1 == offset of current block vs offs string
        OPCODE(buff + i + 0x08, 0x64, 0x00, 0x04, 0xcb);        // sub    x4, x3, x4 = [ 64 00 04 cb ]              x4 == addr of buff + 0x1000
        OPCODE(buff + i + 0x0c, 0x82, 0x00, 0x40, 0xa9);        // ldp    x2, x0, [x4] = [ 82 00 40 a9 ]            w2 == code "DD EC FF 97" at 0x322D8
        OPCODE(buff + i + 0x10, 0x82, 0x00, 0x00, 0xb5);        // cbnz   x2, #0x10 = [ 82 00 00 b5 ]

        OPCODE(buff + i + 0x14, 0xc0, 0x03, 0x5f, 0xd6);        // ret = [ c0 03 5f d6 ]                            x0 == LinuxLoader code size to return
        //OPCODE(buff + i + 0x14, 0x00, 0x00, 0xc0, 0x14);        // b  #0x3000000 = [ 00 00 c0 14 ]]
        *(uint32_t *)(buff + i + 0x18) = i - (0x2000 + i / bs * 16);
        *(uint32_t *)(buff + i + 0x1c) = i - 0x1000;

        OPCODE(buff + i + 0x20, 0x60, 0x00, 0x01, 0xcb);        // sub    x0, x3, x1 = [ 60 00 01 cb ]              x0 == addr of our resp. str. in usb buff
        OPCODE(buff + i + 0x24, 0x61, 0x4c, 0x40, 0xb8);        // ldr    w1, [x3, #0x04]! = [ 61 4c 40 b8 ]
        OPCODE(buff + i + 0x28, 0x3f, 0x00, 0x02, 0x6b);        // cmp    w1, w2 = [ 3f 00 02 6b ]
        OPCODE(buff + i + 0x2c, 0xc1, 0xff, 0xff, 0x54);        // b.ne   #-0x08 = [ c1 ff ff 54 ]                  x3 = call to return fb FAIL (0x322D8)
        OPCODE(buff + i + 0x30, 0xc1, 0x03, 0x03, 0xcb);        // sub    x1, lr, x3 = [ c1 03 03 cb ]
        OPCODE(buff + i + 0x34, 0x21, 0x00, 0x02, 0x8b);        // add    x1, x1, x2 = [ 21 00 02 8b ]
        OPCODE(buff + i + 0x38, 0x01, 0x70, 0x00, 0xf8);        // str    x1, [x0, #0x07] = [ 01 70 00 f8 ]
        OPCODE(buff + i + 0x3c, 0x62, 0x00, 0x02, 0x8b);        // add    x2, x3, x2 = [ 62 00 02 8b ]
        OPCODE(buff + i + 0x40, 0x02, 0xf0, 0x00, 0xf8);        // str    x2, [x0, #0x0f] = [ 02 f0 00 f8 ]
        OPCODE(buff + i + 0x44, 0x9f, 0x00, 0x00, 0xf9);        // str    xzr, [x4] = [ 9f 00 00 f9 ]
        OPCODE(buff + i + 0x48, 0x82, 0x14, 0x41, 0xa9);        // ldp    x2, x5, [x4, #0x10] = [ 82 14 41 a9 ]
        OPCODE(buff + i + 0x4c, 0x62, 0x00, 0x02, 0xcb);        // sub    x2, x3, x2 = [ 62 00 02 cb ]
        OPCODE(buff + i + 0x50, 0x45, 0x00, 0x05, 0x8b);        // add    x5, x2, x5 = [ 45 00 05 8b ]
        OPCODE(buff + i + 0x54, 0xa2, 0x00, 0x00, 0xf9);        // str    x2, [x5] = [ a2 00 00 f9 ]
        OPCODE(buff + i + 0x58, 0x60, 0x00, 0x1f, 0xd6);        // br     x3 = [ 60 00 1f d6 ]                      jump back to 0x322D8

        if (i + bs + 0x5c < size) {
            for (j = 0x5c; j < bs; j += 4) {
                uint8_t b0 = (((bs - j) / 4) >> 0) & 0xff;
                uint8_t b1 = (((bs - j) / 4) >> 8) & 0xff;
                OPCODE(buff + i + j, b0, b1, 0x00, 0x14);       // b      #(bs - j)
            }
        } else {
            for (j = 0x5c; j < bs; j += 4) {
                uint8_t b0 = ((-j / 4) >> 0) & 0xff;
                uint8_t b1 = ((-j / 4) >> 8) & 0xff;
                OPCODE(buff + i + j, b0, b1, 0xff, 0x17);       // b      #(-j)
            }
        }
        //OPCODE(buff + i + 0x58, 0x00, 0x00, 0x00, 0x15);        // b      #0x4000000 = [ 00 00 00 15 ]
    }
}


static void q206_setup_test4(unsigned char *buff, int size, int offset, int payloadsize)
{
    int i;

    memset(buff, 0, 0x80);

    for (i = 0x80; i < size; i += 4)
            OPCODE(buff + i + 0x00, 0xc0, 0x03, 0x5f, 0xd6);    // ret = [ c0 03 5f d6 ]

    for (i = offset; i < size; i += 0x80) {
        OPCODE(buff + i + 0x00, 0x0a, 0x00, 0x00, 0x10);        // adr    x10, #0x00 = [ 0a 00 00 10 ]              x10 == buff
        OPCODE(buff + i + 0x04, 0x40, 0x75, 0x40, 0xb9);        // ldr    w0, [x10, #0x74] = [ 40 75 40 b9 ]        w14 == offset of exploit_continue, w0 == LinuxLoader code size
        OPCODE(buff + i + 0x08, 0x4e, 0x35, 0x4f, 0x29);        // ldp    w14, w13, [x10, #0x78] = [ 4e 35 4f 29 ]  w13 == offset of fastboot_download_512MB_buffer_ptr
        OPCODE(buff + i + 0x0c, 0x02, 0x00, 0x00, 0x14);        // b      #0x08 = [ 02 00 00 14 ]

        OPCODE(buff + i + 0x10, 0xfc, 0xff, 0xff, 0x17);        // b      #-0x10 = [ fc ff ff 17 ]
        OPCODE(buff + i + 0x14, 0x7f, 0x00, 0x00, 0xeb);        // cmp    x3, x0 = [ 7f 00 00 eb ]                  check if called from alternate code path with size in x3
        OPCODE(buff + i + 0x18, 0x61, 0x00, 0x00, 0x54);        // b.ne   #0x0c = [ 61 00 00 54 ]                   if not.eq it is the first call of this code
        OPCODE(buff + i + 0x1c, 0xc0, 0x03, 0x5f, 0xd6);        // ret = [ c0 03 5f d6 ]                            return not doing anything for the 2nd invokation of this

        OPCODE(buff + i + 0x20, 0xf8, 0xff, 0xff, 0x17);        // b      #-0x20 = [ f8 ff ff 17 ]
        OPCODE(buff + i + 0x24, 0x3f, 0x00, 0x08, 0x71);        // cmp    w1, #0x200 = [ 3f 00 08 71 ]              check if called from alternate code path as 1st invocation
        OPCODE(buff + i + 0x28, 0x81, 0x00, 0x00, 0x54);        // b.ne   #0x10 = [ 81 00 00 54 ]
        OPCODE(buff + i + 0x2c, 0x02, 0x00, 0x00, 0x14);        // b      #0x08 = [ 02 00 00 14 ]

        OPCODE(buff + i + 0x30, 0xf4, 0xff, 0xff, 0x17);        // b      #-0x30 = [ f4 ff ff 17 ]
        OPCODE(buff + i + 0x34, 0xde, 0xf3, 0x02, 0xd1);        // sub    lr, lr, #0xbc = [ de f3 02 d1 ]           called from alt code path 1st inv., adjust LR to &exploit_continue
        OPCODE(buff + i + 0x38, 0xce, 0x03, 0x0e, 0xcb);        // sub    x14, lr, x14 = [ ce 03 0e cb ]            x14 == LinuxLoader base addr
        OPCODE(buff + i + 0x3c, 0x02, 0x00, 0x00, 0x14);        // b      #0x08 = [ 02 00 00 14 ]

        OPCODE(buff + i + 0x40, 0xf0, 0xff, 0xff, 0x17);        // b      #-0x40 = [ f0 ff ff 17 ]
        OPCODE(buff + i + 0x44, 0xcc, 0x69, 0x6d, 0xf8);        // ldr    x12, [x14, x13] = [ cc 69 6d f8 ]         x12 = orig fastboot_download_512MB_buffer_ptr
        OPCODE(buff + i + 0x48, 0xce, 0x69, 0x2d, 0xf8);        // str    x14, [x14, x13] = [ ce 69 2d f8 ]         fastboot_download_512MB_buffer_ptr = LinuxLoader base addr
        OPCODE(buff + i + 0x4c, 0x02, 0x00, 0x00, 0x14);        // b      #0x08 = [ 02 00 00 14 ]

        OPCODE(buff + i + 0x50, 0xec, 0xff, 0xff, 0x17);        // b      #-0x50 = [ ec ff ff 17 ]
        OPCODE(buff + i + 0x54, 0x2b, 0x22, 0xa2, 0x52);        // movz   w11, #0x1111, lsl #16 = [ 2b 22 a2 52 ]
        OPCODE(buff + i + 0x58, 0x2b, 0x22, 0x82, 0x72);        // movk   w11, #0x1111 = [ 2b 22 82 72 ]
        OPCODE(buff + i + 0x5c, 0x02, 0x00, 0x00, 0x14);        // b      #0x08 = [ 02 00 00 14 ]

        OPCODE(buff + i + 0x60, 0xe8, 0xff, 0xff, 0x17);        // b      #-0x60 = [ e8 ff ff 17 ]
        //OPCODE(buff + i + 0x64, 0x8f, 0x01, 0x0b, 0x8b);        // add    x15, x12, x11 = [ 8f 01 0b 8b ]           x15 == orig fastboot_download_512MB_buffer_ptr + 0x11111111
        OPCODE(buff + i + 0x64, 0xcf, 0x01, 0x0b, 0x8b);        // add    x15, x14, x11 = [ cf 01 0b 8b ]           x15 == LinuxLoader base addr + 0x11111111
        OPCODE(buff + i + 0x68, 0x6f, 0x32, 0x00, 0xa9);        // stp    x15, x12, [x19] = [ 6f 32 00 a9 ]         *hexlengthptr = x15;   *(hexlengthptr + 8) = x12
        OPCODE(buff + i + 0x6c, 0xc0, 0x03, 0x5f, 0xd6);        // ret = [ c0 03 5f d6 ]                            return to &exploit_continue

        OPCODE(buff + i + 0x70, 0xe4, 0xff, 0xff, 0x17);        // b      #-0x70 = [ e4 ff ff 17 ]
        *(uint32_t *)(buff + i + 0x74) = payloadsize;           //                                                  size of code section of the LinuxLoader.pe
        *(uint32_t *)(buff + i + 0x78) = q206_stage1_cont;      //                                                  offset of exploit_continue
        *(uint32_t *)(buff + i + 0x7c) = 0x11e1f8;              //                                                  offset of fastboot_download_512MB_buffer_ptr
    }
}

static void q206_setup_test5_hitcode(unsigned char *buff, int pos, int jmpto)
{
}


static void q206_setup_test5(unsigned char *buff, int size, int offset, int payloadsize)
{
}

static void q206_test8_patch(unsigned char *ablcode, int size, int offset);

static void q206_patch_abl(unsigned char *ablcode, int extended)
{
}

static const int q206_vb_size = 0xc000;

static void q206_test6_patch(unsigned char *vbcode, int size, int offset)
{
}

static void q206_test7_patch(unsigned char *ablcode, int size, int offset)
{
}

static void q206_test8_patch(unsigned char *ablcode, int size, int offset)
{
}

static void q206_test9_patch(unsigned char *vbcode, int size, int offset)
{
}
