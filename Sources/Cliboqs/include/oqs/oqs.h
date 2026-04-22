/**
 * \file oqs.h
 * \brief Overall header file for the liboqs public API.
 *
 * C programs using liboqs can include just this one file, and it will include all
 * other necessary headers from liboqs.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef OQS_H
#define OQS_H

#include <oqs/oqsconfig.h>

#include <oqs/common.h>
#include <oqs/rand.h>
#include <oqs/rand_nist.h>

#include <oqs/aes.h>
#include <oqs/aes_ops.h>
#include <oqs/sha2.h>
#include <oqs/sha2_ops.h>
#include <oqs/sha3.h>
#include <oqs/sha3_ops.h>
#include <oqs/sha3x4.h>
#include <oqs/sha3x4_ops.h>

#include <oqs/kem.h>
#include <oqs/kem_bike.h>
#include <oqs/kem_classic_mceliece.h>
#include <oqs/kem_frodokem.h>
#include <oqs/kem_hqc.h>
#include <oqs/kem_kyber.h>
#include <oqs/kem_ml_kem.h>
#include <oqs/kem_ntru.h>
#include <oqs/kem_ntruprime.h>

#include <oqs/sig.h>
#include <oqs/sig_cross.h>
#include <oqs/sig_falcon.h>
#include <oqs/sig_mayo.h>
#include <oqs/sig_ml_dsa.h>
#include <oqs/sig_slh_dsa.h>
#include <oqs/sig_snova.h>
#include <oqs/sig_sphincs.h>
#include <oqs/sig_uov.h>

#include <oqs/sig_stfl.h>
#include <oqs/sig_stfl_lms.h>
#include <oqs/sig_stfl_xmss.h>

#endif // OQS_H
