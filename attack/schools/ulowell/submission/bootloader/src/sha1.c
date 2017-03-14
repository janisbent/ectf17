/*
 * sha1 code.
 */

#include "sha1.h"

#define HASHBLOCK_SIZE  64

static uint32_t ft(int t, uint32_t x, uint32_t y, uint32_t z){
    uint32_t a,b,c=0;
    if (t < 20){
        a = x & y;
        b = (~x) & z;
        c = a ^ b;
    }
    else if (t < 40){
        c = x ^ y ^ z;
    }
    else if (t < 60){
        a = x & y;
        b = a ^ (x & z);
        c = b ^ (y & z);
    }
    else if (t < 80){
        c = (x ^ y) ^ z;
    }
    return c;
}

static uint32_t k(int t){
    uint32_t c=0;
    if (t < 20){
        c = 0x5a827999;
    }
    else if (t < 40){
        c = 0x6ed9eba1;
    }
    else if (t < 60){
        c = 0x8f1bbcdc;
    }
    else if (t < 80){
        c = 0xca62c1d6;
    }
    return c;
}

static uint32_t rotl(int bits, uint32_t a){
    uint32_t c,d,e,f,g;
    c = 0xffffffff >> bits;
    d = ~c;
    e = (a & c) << bits;
    f = (a & d) >> (32 - bits);
    g = e | f;

    return (g);
}

// SHA1 initial function
void sha1_init(uint32_t * h)
{
    h[0] = 0x67452301;
    h[1] = 0xefcdab89;
    h[2] = 0x98badcfe;
    h[3] = 0x10325476;
    h[4] = 0xc3d2e1f0;
}

// SHA1 Padding hash block size
void pad_msg(uint8_t *inmsg, uint8_t *msg, int message_length, uint32_t l){
    int i;
    
    for (i = 0; i < HASHBLOCK_SIZE; ++i)
        msg[i] = 0x00;
    for (i = 0; i < message_length; ++i)
        msg[i] = inmsg[i];
    /* insert b1 padding bit */
    if(message_length != 0)
        msg[message_length] = 0x80;
    
    l = l * 8;
    
    msg[HASHBLOCK_SIZE-1] = (uint8_t)( l         );
    msg[HASHBLOCK_SIZE-2] = (uint8_t)((l >> 8)   );
    msg[HASHBLOCK_SIZE-3] = (uint8_t)((l >> 16)  );
    msg[HASHBLOCK_SIZE-4] = (uint8_t)((l >> 24)  );
}

// SHA1 hash block size process function
void sha1_loop(uint32_t *h, unsigned char *message){
    uint32_t a,b,c,d,e;
    uint32_t w[80];
    uint32_t t, temp;
    
    /* Prepare the message schedule */
    for (t=0; t < 80; t++){
        if (t < 16){
            w[t]  = ((uint32_t)(message[t*4])) << 24;
            w[t] += ((uint32_t)(message[t*4 + 1])) << 16;
            w[t] += ((uint32_t)(message[t*4 + 2])) << 8;
            w[t] += ((uint32_t)(message[t*4 + 3]));
        }
        else if (t < 80){
            w[t] = rotl(1,(w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16]));
        }
    }
    
    /* Initialize the five working variables */
    a = h[0];
    b = h[1];
    c = h[2];
    d = h[3];
    e = h[4];
    
    /* iterate a-e 80 times */
    for (t = 0; t < 80; t++){
        temp = (rotl(5,a) + ft(t,b,c,d));
        temp = (temp + e);
        temp = (temp + k(t));
        temp = (temp + w[t]);
        e = d;
        d = c;
        c = rotl(30,b);
        b = a;
        a = temp;
    }

    /* compute the ith intermediate hash value */
    h[0] = (a + h[0]);
    h[1] = (b + h[1]);
    h[2] = (c + h[2]);
    h[3] = (d + h[3]);
    h[4] = (e + h[4]);
}

// SHA1 finail digest generation function
void gen_digest(uint32_t * h, uint8_t *digest){
    digest[3]  = (uint8_t) ( h[0]       );
    digest[2]  = (uint8_t) ((h[0] >> 8) );
    digest[1]  = (uint8_t) ((h[0] >> 16)  );
    digest[0]  = (uint8_t) ((h[0] >> 24)  );
    
    digest[7]  = (uint8_t) ( h[1]        );
    digest[6]  = (uint8_t) ((h[1] >> 8)  );
    digest[5]  = (uint8_t) ((h[1] >> 16)  );
    digest[4]  = (uint8_t) ((h[1] >> 24)  );
    
    digest[11] = (uint8_t) ( h[2]        );
    digest[10] = (uint8_t) ((h[2] >> 8)  );
    digest[9]  = (uint8_t) ((h[2] >> 16)  );
    digest[8]  = (uint8_t) ((h[2] >> 24)  );
    
    digest[15] = (uint8_t) ( h[3]        );
    digest[14] = (uint8_t) ((h[3] >> 8)  );
    digest[13] = (uint8_t) ((h[3] >> 16)  );
    digest[12] = (uint8_t) ((h[3] >> 24)  );
    
    digest[19] = (uint8_t) ( h[4]        );
    digest[18] = (uint8_t) ((h[4] >> 8)  );
    digest[17] = (uint8_t) ((h[4] >> 16)  );
    digest[16] = (uint8_t) ((h[4] >> 24)  );
}





