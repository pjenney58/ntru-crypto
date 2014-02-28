/******************************************************************************
 * NTRU Cryptography Reference Source Code
 * Copyright (c) 2009-2013, by Security Innovation, Inc. All rights reserved. 
 *
 * ntru_crypto_ntru_mgf1.c is a component of ntru-crypto.
 *
 * Copyright (C) 2009-2013  Security Innovation
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 *****************************************************************************/
 
/******************************************************************************
 *
 * File: ntru_crypto_ntru_mgf1.c
 *
 * Contents: Routines implementing MGF-TP-1 and MGF-1.
 *
 *****************************************************************************/

#if defined(linux) && defined(__KERNEL__)
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#else
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#endif
#include "ntru_crypto_ntru_mgf1.h"
#include "ntru_crypto_ntru_convert.h"


/* ntru_mgf1
 *
 * Implements a basic mask-generation function, generating an arbitrary
 * number of octets based on hashing a digest-length string concatenated
 * with a 4-octet counter.
 *
 * The state (string and counter) is initialized when a seed is present.
 *
 * Returns NTRU_OK if successful.
 * Returns NTRU_CRYPTO_HASH_ errors if they occur.
 *
 */

uint32_t
ntru_mgf1(
    uint8_t                *state,      /* in/out - pointer to the state */
    NTRU_CRYPTO_HASH_ALGID  algid,      /*     in - hash algorithm ID */
    uint8_t                 md_len,     /*     in - no. of octets in digest */
    uint8_t                 num_calls,  /*     in - no. of hash calls */
    uint16_t                seed_len,   /*     in - no. of octets in seed */
    uint8_t const          *seed,       /*     in - pointer to seed */
    uint8_t                *out)        /*    out - address for output */
{
    uint8_t  *ctr = state + md_len;
    uint32_t  retcode;
    
#if defined(linux) && defined(__KERNEL__)
    BUG_ON(!state);
    BUG_ON(!out);
#else
    assert(state);
    assert(out);
#endif

    /* if seed present, init state */

    if (seed)
    {
        if ((retcode = ntru_crypto_hash_digest(algid, seed, seed_len, state)) !=
                NTRU_CRYPTO_HASH_OK)
        {
            return retcode;
        }
        
        memset(ctr, 0, 4);
    }

    /* generate output */

    while (num_calls-- > 0)
    {
        if ((retcode = ntru_crypto_hash_digest(algid, state, md_len + 4,
                                 out)) != NTRU_CRYPTO_HASH_OK)
        {
            return retcode;
        }
        
        out += md_len;

        /* increment counter */

        if (++ctr[3] == 0)
        {
            if (++ctr[2] == 0)
            {
                if (++ctr[1] == 0)
                {
                    ++ctr[0];
                }
            }
        }
    }

    NTRU_RET(NTRU_OK);
}


/* ntru_mgftp1
 *
 * Implements a mask-generation function for trinary polynomials,
 * MGF-TP-1, generating an arbitrary number of octets based on hashing
 * a digest-length string concatenated with a 4-octet counter.  From
 * these octets, N trits are derived.
 *
 * The state (string and counter) is initialized when a seed is present.
 *
 * Returns NTRU_OK if successful.
 * Returns NTRU_CRYPTO_HASH_ errors if they occur.
 *
 */

uint32_t
ntru_mgftp1(
    NTRU_CRYPTO_HASH_ALGID  hash_algid,       /*  in - hash alg ID for
                                                       MGF-TP-1 */
    uint8_t                 md_len,           /*  in - no. of octets in
                                                       digest */
    uint8_t                 min_calls,        /*  in - minimum no. of hash
                                                       calls */
    uint16_t                seed_len,         /*  in - no. of octets in seed */
    uint8_t                *seed,             /*  in - pointer to seed */
    uint8_t                *buf,              /*  in - pointer to working
                                                       buffer */
    uint16_t                num_trits_needed, /*  in - no. of trits in mask */
    uint8_t                *mask)             /* out - address for mask trits */
{
    uint8_t  *mgf_out;
    uint8_t  *octets;
    uint16_t  octets_available;
    uint32_t  retcode;

#if defined(linux) && defined(__KERNEL__)
    BUG_ON(!seed);
    BUG_ON(!buf);
    BUG_ON(!mask);
#else
    assert(seed);
    assert(buf);
    assert(mask);
#endif

    /* generate minimum MGF1 output */

    mgf_out = buf + md_len + 4;
    if ((retcode = ntru_mgf1(buf, hash_algid, md_len, min_calls,
                             seed_len, seed, mgf_out)) != NTRU_OK)
    {
        return retcode;
    }
    
    octets = mgf_out;
    octets_available = min_calls * md_len;

    /* get trits for mask */

    while (num_trits_needed >= 5)
    {

        /* get another octet and convert it to 5 trits */

        if (octets_available == 0)
        {
            if ((retcode = ntru_mgf1(buf, hash_algid, md_len, 1,
                                     0, NULL, mgf_out)) != NTRU_OK)
            {
                return retcode;
            }
            
            octets = mgf_out;
            octets_available = md_len;
        }

        if (*octets < 243)
        {
            ntru_octet_2_trits(*octets, mask);
            mask += 5;
            num_trits_needed -= 5;
        }
        
        octets++;
        --octets_available;
    }

    /* get any remaining trits */

    while (num_trits_needed)
    {
        uint8_t trits[5];

        /* get another octet and convert it to remaining trits */

        if (octets_available == 0)
        {
            if ((retcode = ntru_mgf1(buf, hash_algid, md_len, 1,
                                     0, NULL, mgf_out)) != NTRU_OK)
            {
                return retcode;
            }
            
            octets = mgf_out;
            octets_available = md_len;
        }
        
        if (*octets < 243)
        {
            ntru_octet_2_trits(*octets, trits);
            memcpy(mask, trits, num_trits_needed);
            num_trits_needed = 0;
        }
        else
        {
            octets++;
            --octets_available;
        }
    }

    NTRU_RET(NTRU_OK);
}


