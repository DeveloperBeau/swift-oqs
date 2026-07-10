#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VERSION=$(cat "$REPO_ROOT/LIBOQS_VERSION")
DEST="$REPO_ROOT/Sources/Cliboqs"

echo "Vendoring liboqs $VERSION..."

# Hand-maintained files preserved across re-vendoring (paths relative to
# $DEST). None have an upstream counterpart in the release tarball: oqsconfig.h
# is our build config, oqs_safe.h is ours (SafeInteropWrappers), and the
# mlkem-native / mldsa-native fallback config headers are hand-added (they
# supply the per-variant parameter set that liboqs's CMake passes via
# -DML{K,D}_CONFIG_FILE, which SPM cannot do per-target). (oqs.h is NOT
# preserved — it is regenerated below from the vendored header set.)
PRESERVE=(
    "include/oqs/oqsconfig.h"
    "include/oqs/oqs_safe.h"
    "src/kem/ml_kem/mlkem-native_ml-kem-512_ref/mlkem/src/mlkem_native_config.h"
    "src/kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/mlkem_native_config.h"
    "src/kem/ml_kem/mlkem-native_ml-kem-1024_ref/mlkem/src/mlkem_native_config.h"
    "src/sig/ml_dsa/mldsa-native_ml-dsa-44_ref/mldsa/src/mldsa_native_config.h"
    "src/sig/ml_dsa/mldsa-native_ml-dsa-65_ref/mldsa/src/mldsa_native_config.h"
    "src/sig/ml_dsa/mldsa-native_ml-dsa-87_ref/mldsa/src/mldsa_native_config.h"
)
BACKUP=$(mktemp -d)
for rel in "${PRESERVE[@]}"; do
    if [ -f "$DEST/$rel" ]; then
        mkdir -p "$BACKUP/$(dirname "$rel")"
        cp "$DEST/$rel" "$BACKUP/$rel"
    fi
done

if [ -d "$DEST/src" ]; then
    rm -rf "$DEST/src"
fi
if [ -d "$DEST/include/oqs" ]; then
    rm -rf "$DEST/include/oqs"
fi

TMPDIR=$(mktemp -d)
TARBALL="$TMPDIR/liboqs-$VERSION.tar.gz"
curl -sL "https://github.com/open-quantum-safe/liboqs/archive/refs/tags/$VERSION.tar.gz" -o "$TARBALL"
tar -xzf "$TARBALL" -C "$TMPDIR"
LIBOQS_SRC="$TMPDIR/liboqs-$VERSION/src"

mkdir -p "$DEST/src"
cp -R "$LIBOQS_SRC/common" "$DEST/src/"
cp -R "$LIBOQS_SRC/kem" "$DEST/src/"
cp -R "$LIBOQS_SRC/sig" "$DEST/src/"
cp -R "$LIBOQS_SRC/sig_stfl" "$DEST/src/"

mkdir -p "$DEST/include/oqs"

# Core public headers
cp "$LIBOQS_SRC/common/common.h" "$DEST/include/oqs/"
cp "$LIBOQS_SRC/common/rand/rand.h" "$DEST/include/oqs/"
cp "$LIBOQS_SRC/common/rand/rand_nist.h" "$DEST/include/oqs/" 2>/dev/null || true
cp "$LIBOQS_SRC/kem/kem.h" "$DEST/include/oqs/"
cp "$LIBOQS_SRC/sig/sig.h" "$DEST/include/oqs/"
cp "$LIBOQS_SRC/sig_stfl/sig_stfl.h" "$DEST/include/oqs/"
cp "$LIBOQS_SRC/sig_stfl/xmss/sig_stfl_xmss.h" "$DEST/include/oqs/"
cp "$LIBOQS_SRC/sig_stfl/lms/sig_stfl_lms.h" "$DEST/include/oqs/"
cp "$LIBOQS_SRC/common/aes/aes_ops.h" "$DEST/include/oqs/"
cp "$LIBOQS_SRC/common/aes/aes.h" "$DEST/include/oqs/"
cp "$LIBOQS_SRC/common/sha2/sha2_ops.h" "$DEST/include/oqs/"
cp "$LIBOQS_SRC/common/sha2/sha2.h" "$DEST/include/oqs/"
cp "$LIBOQS_SRC/common/sha3/sha3_ops.h" "$DEST/include/oqs/"
cp "$LIBOQS_SRC/common/sha3/sha3.h" "$DEST/include/oqs/"
cp "$LIBOQS_SRC/common/sha3/sha3x4_ops.h" "$DEST/include/oqs/"
cp "$LIBOQS_SRC/common/sha3/sha3x4.h" "$DEST/include/oqs/"

# Per-algorithm public headers (kem_*.h, sig_*.h at algorithm directory level)
for dir in "$LIBOQS_SRC"/kem/*/; do
    for h in "$dir"kem_*.h; do
        [ -f "$h" ] && cp "$h" "$DEST/include/oqs/"
    done
done
for dir in "$LIBOQS_SRC"/sig/*/; do
    for h in "$dir"sig_*.h; do
        [ -f "$h" ] && cp "$h" "$DEST/include/oqs/"
    done
done

# Regenerate the umbrella header from the vendored header set. Upstream's
# oqs.h only includes kem.h/sig.h/sig_stfl.h; the Swift module needs every
# public header pulled in, and the per-algorithm set changes across releases,
# so it is derived here rather than hand-patched or copied from upstream.
{
    cat <<'EOF'
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
EOF
    [ -f "$DEST/include/oqs/rand_nist.h" ] && echo "#include <oqs/rand_nist.h>"
    cat <<'EOF'

#include <oqs/aes.h>
#include <oqs/aes_ops.h>
#include <oqs/sha2.h>
#include <oqs/sha2_ops.h>
#include <oqs/sha3.h>
#include <oqs/sha3_ops.h>
#include <oqs/sha3x4.h>
#include <oqs/sha3x4_ops.h>

#include <oqs/kem.h>
EOF
    for h in "$DEST/include/oqs"/kem_*.h; do
        echo "#include <oqs/$(basename "$h")>"
    done
    echo ""
    echo "#include <oqs/sig.h>"
    for h in "$DEST/include/oqs"/sig_*.h; do
        case "$(basename "$h")" in sig_stfl*) continue ;; esac
        echo "#include <oqs/$(basename "$h")>"
    done
    echo ""
    echo "#include <oqs/sig_stfl.h>"
    echo "#include <oqs/sig_stfl_lms.h>"
    echo "#include <oqs/sig_stfl_xmss.h>"
    echo ""
    echo "#endif // OQS_H"
} > "$DEST/include/oqs/oqs.h"

# generate_unity <family_dir> <variant_dir_glob> [extra_defines...]
# Emits one unity_<variant>.c per matching variant directory that #includes
# every .c file directly inside that directory (non-recursive). Concatenating
# per-variant sources into one TU avoids SPM's flat per-basename object
# collisions across variants that share filenames (poly.c, ntt.c, ...).
# extra_defines are emitted as `#define <token>` at the top of the TU (note:
# pass "NAME VAL" with a space, not CMake's -DNAME=VAL form) so per-variant
# compile-time parameters that liboqs's CMake passes via -D — which SPM cannot
# supply per-file — are baked into the TU ahead of the variant's params.h
# (whose defaults are #ifndef-guarded).
generate_unity() {
    local family_dir="$1"; shift
    local glob="$1"; shift
    local defines=("$@")
    local vdir base unity f d
    local matched=0
    for vdir in "$DEST/$family_dir"/$glob; do
        [ -d "$vdir" ] || continue
        matched=1
        base="$(basename "$vdir")"
        unity="$DEST/$family_dir/unity_${base}.c"
        {
            echo "/* GENERATED by scripts/vendor-liboqs.sh — do not edit. */"
            for d in "${defines[@]}"; do echo "#define $d"; done
            for f in "$vdir"/*.c; do
                [ -e "$f" ] || continue
                echo "#include \"${base}/$(basename "$f")\""
            done
        } > "$unity"
        echo "  generated $unity"
    done
    if [ "$matched" -eq 0 ]; then
        echo "error: no variant directory matched $family_dir/$glob — upstream renamed or removed it; update this script" >&2
        exit 1
    fi
}

# ML-DSA (mldsa-native, 0.16.0+) compiles its _ref variant dirs as plain TUs,
# exactly like ml_kem: symbols are namespaced per parameter set by the
# hand-added mldsa/src/mldsa_native_config.h in each variant dir (see
# PRESERVE). No unity TU is needed.

# Kyber variants take their security level from KYBER_K (CMake -DKYBER_K=N).
generate_unity "src/kem/kyber" "pqcrystals-kyber_kyber512_ref"  "KYBER_K 2"
generate_unity "src/kem/kyber" "pqcrystals-kyber_kyber768_ref"  "KYBER_K 3"
generate_unity "src/kem/kyber" "pqcrystals-kyber_kyber1024_ref" "KYBER_K 4"

# SNOVA variants take v/o/l + sk_is_seed + PK_EXPAND_SHAKE + OPTIMISATION from
# CMake -D flags. OPTIMISATION must be 1 (opt path); params.h defaults it to 2
# (SIMD). Values mirror src/sig/snova/CMakeLists.txt.
generate_unity "src/sig/snova" "snova_SNOVA_24_5_4_opt"          "OPTIMISATION 1" "v_SNOVA 24" "o_SNOVA 5"  "l_SNOVA 4" "sk_is_seed 1" "PK_EXPAND_SHAKE 0"
generate_unity "src/sig/snova" "snova_SNOVA_24_5_4_SHAKE_opt"    "OPTIMISATION 1" "v_SNOVA 24" "o_SNOVA 5"  "l_SNOVA 4" "sk_is_seed 1" "PK_EXPAND_SHAKE 1"
generate_unity "src/sig/snova" "snova_SNOVA_24_5_4_esk_opt"      "OPTIMISATION 1" "v_SNOVA 24" "o_SNOVA 5"  "l_SNOVA 4" "sk_is_seed 0" "PK_EXPAND_SHAKE 0"
generate_unity "src/sig/snova" "snova_SNOVA_24_5_4_SHAKE_esk_opt" "OPTIMISATION 1" "v_SNOVA 24" "o_SNOVA 5"  "l_SNOVA 4" "sk_is_seed 0" "PK_EXPAND_SHAKE 1"
generate_unity "src/sig/snova" "snova_SNOVA_24_5_5_opt"          "OPTIMISATION 1" "v_SNOVA 24" "o_SNOVA 5"  "l_SNOVA 5" "sk_is_seed 1" "PK_EXPAND_SHAKE 0"
generate_unity "src/sig/snova" "snova_SNOVA_25_8_3_opt"          "OPTIMISATION 1" "v_SNOVA 25" "o_SNOVA 8"  "l_SNOVA 3" "sk_is_seed 1" "PK_EXPAND_SHAKE 0"
generate_unity "src/sig/snova" "snova_SNOVA_29_6_5_opt"          "OPTIMISATION 1" "v_SNOVA 29" "o_SNOVA 6"  "l_SNOVA 5" "sk_is_seed 1" "PK_EXPAND_SHAKE 0"
generate_unity "src/sig/snova" "snova_SNOVA_37_8_4_opt"          "OPTIMISATION 1" "v_SNOVA 37" "o_SNOVA 8"  "l_SNOVA 4" "sk_is_seed 1" "PK_EXPAND_SHAKE 0"
generate_unity "src/sig/snova" "snova_SNOVA_37_17_2_opt"         "OPTIMISATION 1" "v_SNOVA 37" "o_SNOVA 17" "l_SNOVA 2" "sk_is_seed 1" "PK_EXPAND_SHAKE 0"
generate_unity "src/sig/snova" "snova_SNOVA_49_11_3_opt"         "OPTIMISATION 1" "v_SNOVA 49" "o_SNOVA 11" "l_SNOVA 3" "sk_is_seed 1" "PK_EXPAND_SHAKE 0"
generate_unity "src/sig/snova" "snova_SNOVA_56_25_2_opt"         "OPTIMISATION 1" "v_SNOVA 56" "o_SNOVA 25" "l_SNOVA 2" "sk_is_seed 1" "PK_EXPAND_SHAKE 0"
generate_unity "src/sig/snova" "snova_SNOVA_60_10_4_opt"         "OPTIMISATION 1" "v_SNOVA 60" "o_SNOVA 10" "l_SNOVA 4" "sk_is_seed 1" "PK_EXPAND_SHAKE 0"

# MAYO opt variants select their parameter set from MAYO_VARIANT (CMake
# -DMAYO_VARIANT=MAYO_N). MAYO angle-includes its own variant-local headers
# (mayo.h, api.h, params.h, ...) whose sizes differ per variant, so they cannot
# share a flat include path. Rather than rewrite the upstream sources, each opt
# variant is compiled as its own SPM sub-target (CliboqsMAYO{1,2,3,5} in
# Package.swift) with its own directory on the header search path and the
# per-variant -D parameter defines, leaving the upstream sources pristine.

# UOV (oil-and-vinegar) variants select their param triple (_OVk_v_o), public-
# key/secret-key compression mode (_OV_CLASSIC / _OV_PKC / _OV_PKC_SKC), and
# hash backend from CMake -D flags. We pin _UTILS_OQS_ so utils_hash.c uses
# liboqs's bundled SHA3 (<oqs/sha3.h>) instead of OpenSSL, keeping the package
# dependency-free. UOV quote-includes its own variant-local headers, so no
# localize_includes is needed. Values mirror src/sig/uov/CMakeLists.txt.
generate_unity "src/sig/uov" "pqov_ov_Is_ref"           "_OV16_160_64"  "_OV_CLASSIC"  "_UTILS_OQS_"
generate_unity "src/sig/uov" "pqov_ov_Ip_ref"           "_OV256_112_44" "_OV_CLASSIC"  "_UTILS_OQS_"
generate_unity "src/sig/uov" "pqov_ov_III_ref"          "_OV256_184_72" "_OV_CLASSIC"  "_UTILS_OQS_"
generate_unity "src/sig/uov" "pqov_ov_V_ref"            "_OV256_244_96" "_OV_CLASSIC"  "_UTILS_OQS_"
generate_unity "src/sig/uov" "pqov_ov_Is_pkc_ref"       "_OV16_160_64"  "_OV_PKC"      "_UTILS_OQS_"
generate_unity "src/sig/uov" "pqov_ov_Ip_pkc_ref"       "_OV256_112_44" "_OV_PKC"      "_UTILS_OQS_"
generate_unity "src/sig/uov" "pqov_ov_III_pkc_ref"      "_OV256_184_72" "_OV_PKC"      "_UTILS_OQS_"
generate_unity "src/sig/uov" "pqov_ov_V_pkc_ref"        "_OV256_244_96" "_OV_PKC"      "_UTILS_OQS_"
generate_unity "src/sig/uov" "pqov_ov_Is_pkc_skc_ref"   "_OV16_160_64"  "_OV_PKC_SKC"  "_UTILS_OQS_"
generate_unity "src/sig/uov" "pqov_ov_Ip_pkc_skc_ref"   "_OV256_112_44" "_OV_PKC_SKC"  "_UTILS_OQS_"
generate_unity "src/sig/uov" "pqov_ov_III_pkc_skc_ref"  "_OV256_184_72" "_OV_PKC_SKC"  "_UTILS_OQS_"
generate_unity "src/sig/uov" "pqov_ov_V_pkc_skc_ref"    "_OV256_244_96" "_OV_PKC_SKC"  "_UTILS_OQS_"

# HQC (pqc-hqc, 20250822 spec, 0.16.0+): three ref variant dirs with identical
# basenames and variant-local headers (quote-included, like UOV). Symbols are
# namespaced via PQCHQC_NAMESPACE_PREFIX; USE_OQS_RANDOMBYTES selects liboqs's
# RNG. Values mirror src/kem/hqc/CMakeLists.txt. The glue kem_hqc_N.c compiles
# normally in the main target.
generate_unity "src/kem/hqc" "pqc-hqc_hqc-1_ref" "HQC_ARCH_REF 1" "PQCHQC_NAMESPACE_PREFIX PQCHQC_HQC1_C_" "USE_OQS_RANDOMBYTES"
generate_unity "src/kem/hqc" "pqc-hqc_hqc-3_ref" "HQC_ARCH_REF 1" "PQCHQC_NAMESPACE_PREFIX PQCHQC_HQC3_C_" "USE_OQS_RANDOMBYTES"
generate_unity "src/kem/hqc" "pqc-hqc_hqc-5_ref" "HQC_ARCH_REF 1" "PQCHQC_NAMESPACE_PREFIX PQCHQC_HQC5_C_" "USE_OQS_RANDOMBYTES"

# BIKE keeps ALL sources in one additional_r4 dir, compiled three times with a
# different LEVEL/FUNC_PREFIX (CMake -DLEVEL=N -DFUNC_PREFIX=OQS_KEM_bike_lN).
# Emit one unity TU per level that bakes in those defines, force-includes
# functions_renaming.h (which liboqs's CMake supplies via `-include`, not a
# normal #include — it namespaces every symbol by FUNC_PREFIX, so it MUST be
# included after FUNC_PREFIX is defined and before the sources), then includes
# the portable .c set (avx2/avx512/pclmul/vpclmul + noop_main.c excluded). LEVEL
# drives the parameter sizes in bike_defs.h. The glue kem_bike.c compiles once
# (SPM, no -include) and references all three levels by full name — leave it.
generate_bike_unity() {
    local fam="src/kem/bike"
    local files=(decode.c decode_portable.c error.c gf2x_inv.c gf2x_ksqr_portable.c gf2x_mul.c gf2x_mul_base_portable.c gf2x_mul_portable.c kem.c sampling.c sampling_portable.c shake_prf.c utilities.c)
    local lvl f
    for lvl in 1 3 5; do
        local out="$DEST/$fam/unity_bike_l${lvl}.c"
        {
            echo "/* GENERATED by scripts/vendor-liboqs.sh — do not edit. */"
            echo "#define LEVEL ${lvl}"
            echo "#define FUNC_PREFIX OQS_KEM_bike_l${lvl}"
            echo "#include \"functions_renaming.h\""
            for f in "${files[@]}"; do
                # utilities.c and gf2x_ksqr_portable.c both define BITS_IN_BYTE
                # (8ULL vs (8)); equal values but concatenating them in one unity
                # TU trips -Wmacro-redefined. Clear it before utilities.c.
                if [ "$f" = "utilities.c" ]; then echo "#undef BITS_IN_BYTE"; fi
                echo "#include \"additional_r4/${f}\""
            done
        } > "$out"
        echo "  generated $out"
    done
}

generate_bike_unity

# MQOM (0.16.0+): all sources live in shared mqom_mqom_common/, compiled once
# per variant with a distinct -D set (namespaces + MQOM2_PARAM_* + feature
# flags) — BIKE's shape. One unity TU per *_default variant bakes in the
# defines parsed from that variant's add_library/target_compile_options pair
# in src/sig/mqom/CMakeLists.txt (programmatic, like xmss: a wrong define set
# still links and roundtrips, so it must come from source). The glue
# sig_mqom_<variant>.c is part of the variant's CMake source list (it needs
# the same namespace defines), so it is #included in the TU, not compiled
# separately. memopt/avx2 variants are not built.
generate_mqom_unity() {
    local fam="src/sig/mqom"
    local cmake="$DEST/$fam/CMakeLists.txt"
    local emitted=0
    local target="" line
    while IFS= read -r line; do
        case "$line" in
            *"add_library(mqom_mqom2_"*"_default OBJECT"*)
                target="$(printf '%s\n' "$line" | grep -oE 'mqom_mqom2_[a-z0-9_]+_default' | head -1 || true)"
                ;;
            *target_compile_options*MQOM2_FOR_LIBOQS*)
                if [ -n "$target" ] && printf '%s\n' "$line" | grep -q "($target "; then
                    # e.g. mqom_mqom2_cat1_gf16_fast_r3_default -> mqom2_cat1_gf16_fast_r3
                    local variant="${target#mqom_}"; variant="${variant%_default}"
                    local out="$DEST/$fam/unity_${target}.c"
                    {
                        echo "/* GENERATED by scripts/vendor-liboqs.sh — do not edit. */"
                        # -DNAME=VAL -> #define NAME VAL ; -DNAME -> #define NAME
                        printf '%s\n' "$line" | grep -oE '\-D[A-Za-z0-9_]+(=[A-Za-z0-9_./"-]+)?' | sort -u | \
                            sed -e 's/^-D//' -e 's/=/ /' -e 's/^/#define /'
                        echo "#include \"sig_mqom_${variant}.c\""
                        for f in "$DEST/$fam/mqom_mqom_common"/*.c; do
                            local b="$(basename "$f")"
                            # Static-name collisions between files that CMake
                            # compiles as separate TUs but the unity TU
                            # concatenates: rename them per file via macros.
                            case "$b" in
                                rijndael_ref.c)
                                    echo "#define sbox mqom_rijndael_ref_sbox"
                                    echo "#define rcon mqom_rijndael_ref_rcon"
                                    ;;
                                rijndael_ct64.c)
                                    # rijndael_ct64_enc.h defines its own
                                    # static sbox[]/rcon[] copies
                                    echo "#define sbox mqom_rijndael_ct64_sbox"
                                    echo "#define rcon mqom_rijndael_ct64_rcon"
                                    ;;
                                piop_memopt.c)
                                    echo "#define ExpandBatchingChallenge mqom_piop_memopt_ExpandBatchingChallenge"
                                    ;;
                            esac
                            echo "#include \"mqom_mqom_common/$b\""
                            case "$b" in
                                rijndael_ref.c|rijndael_ct64.c)
                                    echo "#undef sbox"
                                    echo "#undef rcon"
                                    ;;
                                piop_memopt.c)
                                    echo "#undef ExpandBatchingChallenge"
                                    ;;
                            esac
                        done
                    } > "$out"
                    echo "  generated $out"
                    emitted=$((emitted + 1))
                    target=""
                fi
                ;;
        esac
    done < "$cmake"
    if [ "$emitted" -ne 12 ]; then
        echo "error: parsed $emitted MQOM default variants from $cmake, expected 12 — upstream CMakeLists format changed; update this script" >&2
        exit 1
    fi
}

generate_mqom_unity

# XMSS/XMSSMT: 37 variants, each compiled by liboqs's CMake as its own OBJECT
# target with a per-variant -DXMSS_PARAMS_NAMESPACE and -DHASH (HASH selects the
# hash primitive; its value is NON-OBVIOUS — 7 distinct codes across the sha256/
# shake128/sha512/shake256 + _192/_256 families). We mirror that by emitting one
# unity TU per variant that bakes in those two defines and #includes the variant
# file, the (namespaced) sig_stfl_xmss[mt]_functions.c, and the shared external/
# SRCS — concatenating them into one TU so the namespaced symbols are produced
# once per variant without flat per-basename object collisions across variants.
#
# The (variant-file, namespace, HASH, is-mt) tuples are extracted PROGRAMMATICALLY
# from the authoritative src/sig_stfl/xmss/CMakeLists.txt (the add_library + the
# matching target_compile_options lines), never hand-transcribed — a wrong HASH
# still links and roundtrips (internally consistent) so it must come from source.
# XMSS quote-includes its own headers, so no include rewriting is needed.
generate_xmss_unity() {
    local fam="src/sig_stfl/xmss"
    local cmake="$DEST/$fam/CMakeLists.txt"
    # Shared external SRCS, in CMake order.
    local srcs=(core_hash.c hash.c hash_address.c params.c utils.c wots.c xmss.c xmss_commons.c xmss_core_fast.c)
    # Parse: each variant is an add_library line naming its variant .c +
    # sig_stfl_xmss[mt]_functions.c, immediately followed (next non-blank) by a
    # target_compile_options line carrying -DXMSS_PARAMS_NAMESPACE=<ns> -DHASH=<n>.
    local variant_file="" funcs_file="" ns="" hash="" emitted=0
    while IFS= read -r line; do
        case "$line" in
            *add_library*OBJECT*)
                # e.g. add_library(xmss_sha256_h10 OBJECT sig_stfl_xmss_sha256_h10.c sig_stfl_xmss_functions.c ${SRCS})
                # `|| true`: helper targets (e.g. sig_stfl_xmss_secret_key_functions)
                # match the case but yield no variant file — grep's no-match exit 1
                # would kill the script under pipefail. Empty vars just skip emission.
                variant_file="$(printf '%s\n' "$line" | grep -oE 'sig_stfl_xmss(mt)?_[a-z0-9_]+\.c' | grep -vE 'functions\.c' | head -1 || true)"
                funcs_file="$(printf '%s\n' "$line" | grep -oE 'sig_stfl_xmss(mt)?_functions\.c' | head -1 || true)"
                ;;
            *target_compile_options*XMSS_PARAMS_NAMESPACE*)
                ns="$(printf '%s\n' "$line" | grep -oE 'XMSS_PARAMS_NAMESPACE=[a-z0-9_]+' | cut -d= -f2)"
                hash="$(printf '%s\n' "$line" | grep -oE 'HASH=[0-9]+' | cut -d= -f2)"
                if [ -n "$variant_file" ] && [ -n "$funcs_file" ] && [ -n "$ns" ] && [ -n "$hash" ]; then
                    local stem="${variant_file%.c}"
                    local out="$DEST/$fam/unity_${stem}.c"
                    {
                        echo "/* GENERATED by scripts/vendor-liboqs.sh — do not edit. */"
                        echo "#define XMSS_PARAMS_NAMESPACE $ns"
                        echo "#define HASH $hash"
                        echo "#include \"$funcs_file\""
                        echo "#include \"$variant_file\""
                        for s in "${srcs[@]}"; do echo "#include \"external/$s\""; done
                    } > "$out"
                    echo "  generated $out (ns=$ns HASH=$hash)"
                    emitted=$((emitted + 1))
                fi
                variant_file=""; funcs_file=""; ns=""; hash=""
                ;;
        esac
    done < "$cmake"
    if [ "$emitted" -eq 0 ]; then
        echo "error: parsed no XMSS variants from $cmake — upstream CMakeLists format changed; update this script" >&2
        exit 1
    fi
}

generate_xmss_unity

# Fetch upstream KAT hash manifests for cross-checking (best-effort, reference-only).
# Kept OUTSIDE Tests/OQSTests/Vectors so the test bundle stays small.
KAT_DIR="$REPO_ROOT/Tests/OQSTests/UpstreamKATs"
mkdir -p "$KAT_DIR"
if [ -d "$TMPDIR/liboqs-$VERSION/tests/KATs" ]; then
    cp -R "$TMPDIR/liboqs-$VERSION/tests/KATs" "$KAT_DIR/" 2>/dev/null || true
fi

rm -rf "$TMPDIR"

# Restore hand-maintained files over the freshly vendored tree. A preserved
# file whose destination directory no longer exists means upstream renamed the
# layout out from under us — fail loudly rather than drop the file.
for rel in "${PRESERVE[@]}"; do
    if [ -f "$BACKUP/$rel" ]; then
        if [ -d "$DEST/$(dirname "$rel")" ]; then
            cp "$BACKUP/$rel" "$DEST/$rel"
        else
            echo "error: preserved $rel has no destination directory after re-vendor — upstream layout changed; update this script" >&2
            exit 1
        fi
    fi
done
rm -rf "$BACKUP"

echo "Done. Vendored liboqs $VERSION into $DEST"
