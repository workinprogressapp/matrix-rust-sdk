#!/usr/bin/env bash
set -eEu

cd "$(dirname "$0")"

# Path to the repo root
SRC_ROOT=../..

TARGET_DIR="${SRC_ROOT}/target"

GENERATED_DIR="${SRC_ROOT}/generated"
if [ -d "${GENERATED_DIR}" ]; then rm -rf "${GENERATED_DIR}"; fi
mkdir -p ${GENERATED_DIR}/{macos,simulator,watchos,watchos-simulator}

REL_FLAG="--release"
REL_TYPE_DIR="release"

TARGET_CRATE=matrix-sdk-crypto-ffi

# Build static libs for all the different architectures

# iOS
echo -e "Building for iOS [1/9]"
# cargo build -p ${TARGET_CRATE} ${REL_FLAG} --target "aarch64-apple-ios"

# macOS
echo -e "\nBuilding for macOS (Apple Silicon) [2/9]"
cargo build -p ${TARGET_CRATE} ${REL_FLAG} --target "aarch64-apple-darwin"
# echo -e "\nBuilding for macOS (Intel) [3/9]"
# cargo build -p ${TARGET_CRATE} ${REL_FLAG} --target "x86_64-apple-darwin"

# iOS Simulator
# echo -e "\nBuilding for iOS Simulator (Apple Silicon) [4/9]"
# cargo build -p ${TARGET_CRATE} ${REL_FLAG} --target "aarch64-apple-ios-sim"
# echo -e "\nBuilding for iOS Simulator (Intel) [5/9]"
# cargo build -p ${TARGET_CRATE} ${REL_FLAG} --target "x86_64-apple-ios"

# watchOS
echo -e "\nBuilding for watchOS (ARM 64_32) [6/9]"
cargo build -p ${TARGET_CRATE} ${REL_FLAG} -Zbuild-std --target "arm64_32-apple-watchos"
echo -e "\nBuilding for watchOS Simulator (ARM 32) [7/9]"
cargo build -p ${TARGET_CRATE} ${REL_FLAG} -Zbuild-std --target "armv7k-apple-watchos"

# # watchOS Simulator
echo -e "\nBuilding for watchOS Simulator (Apple Silicon) [8/9]"
cargo build -p ${TARGET_CRATE} ${REL_FLAG} -Zbuild-std --target "aarch64-apple-watchos-sim"
# echo -e "\nBuilding for watchOS Simulator (Intel) [9/9]"
# cargo build -p ${TARGET_CRATE} ${REL_FLAG} -Zbuild-std --target "x86_64-apple-watchos-sim"

echo -e "\nLipo Binaries"
# Lipo together the libraries for the same platform

# # macOS
# lipo -create \
#   "${TARGET_DIR}/x86_64-apple-darwin/${REL_TYPE_DIR}/libmatrix_sdk_crypto_ffi.a" \
#   "${TARGET_DIR}/aarch64-apple-darwin/${REL_TYPE_DIR}/libmatrix_sdk_crypto_ffi.a" \
#   -output "${GENERATED_DIR}/macos/libmatrix_sdk_crypto_ffi.a"
# 
# # iOS Simulator
# lipo -create \
#   "${TARGET_DIR}/x86_64-apple-ios/${REL_TYPE_DIR}/libmatrix_sdk_crypto_ffi.a" \
#   "${TARGET_DIR}/aarch64-apple-ios-sim/${REL_TYPE_DIR}/libmatrix_sdk_crypto_ffi.a" \
#   -output "${GENERATED_DIR}/simulator/libmatrix_sdk_crypto_ffi.a"

# watchOS
  lipo -create \
    "${TARGET_DIR}/arm64_32-apple-watchos/${REL_TYPE_DIR}/libmatrix_sdk_crypto_ffi.a" \
    "${TARGET_DIR}/armv7k-apple-watchos/${REL_TYPE_DIR}/libmatrix_sdk_crypto_ffi.a" \
    -output "${GENERATED_DIR}/watchos/libmatrix_sdk_crypto_ffi.a"

# watchOS Simulator
  # lipo -create \
  #   "${TARGET_DIR}/aarch64-apple-watchos-sim/${REL_TYPE_DIR}/libmatrix_sdk_crypto_ffi.a" \
  #   "${TARGET_DIR}/x86_64-apple-watchos-sim/${REL_TYPE_DIR}/libmatrix_sdk_crypto_ffi.a" \
  #   -output "${GENERATED_DIR}/watchos-simulator/libmatrix_sdk_crypto_ffi.a"

echo -e "\nGernerating Uniffi Bindings"
# Generate uniffi files
cargo uniffi-bindgen generate \
  --language swift \
  --lib-file "${TARGET_DIR}/arm64_32-apple-watchos/${REL_TYPE_DIR}/libmatrix_sdk_crypto_ffi.a" \
  --config "${SRC_ROOT}/bindings/${TARGET_CRATE}/uniffi.toml" \
  --out-dir ${GENERATED_DIR} \
  "${SRC_ROOT}/bindings/${TARGET_CRATE}/src/olm.udl"

# Move headers to the right place
HEADERS_DIR=${GENERATED_DIR}/headers
mkdir -p ${HEADERS_DIR}
mv ${GENERATED_DIR}/*.h ${HEADERS_DIR}

# Rename and move modulemap to the right place
mv ${GENERATED_DIR}/*.modulemap ${HEADERS_DIR}/module.modulemap

# Move source files to the right place
SWIFT_DIR="${GENERATED_DIR}/Sources"
mkdir -p ${SWIFT_DIR}
mv ${GENERATED_DIR}/*.swift ${SWIFT_DIR}

# Build the xcframework

if [ -d "${GENERATED_DIR}/MatrixSDKCryptoFFI.xcframework" ]; then rm -rf "${GENERATED_DIR}/MatrixSDKCryptoFFI.xcframework"; fi

echo -e "\nCreating Framework"
xcodebuild -create-xcframework \
  -library "${GENERATED_DIR}/watchos/libmatrix_sdk_crypto_ffi.a" \
  -headers ${HEADERS_DIR} \
  -library "${TARGET_DIR}/aarch64-apple-watchos-sim/${REL_TYPE_DIR}/libmatrix_sdk_crypto_ffi.a" \
  -headers ${HEADERS_DIR} \
  -output "${GENERATED_DIR}/MatrixSDKCryptoFFI.xcframework"
  # -library "${TARGET_DIR}/aarch64-apple-ios/${REL_TYPE_DIR}/libmatrix_sdk_crypto_ffi.a" \
  # -headers ${HEADERS_DIR} \
  # -library "${GENERATED_DIR}/macos/libmatrix_sdk_crypto_ffi.a" \
  # -headers ${HEADERS_DIR} \
  # -library "${GENERATED_DIR}/simulator/libmatrix_sdk_crypto_ffi.a" \
  # -headers ${HEADERS_DIR} \

echo -e "\nCleanup"
# Cleanup
if [ -d "${GENERATED_DIR}/macos" ]; then rm -rf "${GENERATED_DIR}/macos"; fi
if [ -d "${GENERATED_DIR}/simulator" ]; then rm -rf "${GENERATED_DIR}/simulator"; fi
if [ -d "${GENERATED_DIR}/watchos" ]; then rm -rf "${GENERATED_DIR}/watchos"; fi
if [ -d "${GENERATED_DIR}/watchos-simulator" ]; then rm -rf "${GENERATED_DIR}/watchos-simulator"; fi
if [ -d ${HEADERS_DIR} ]; then rm -rf ${HEADERS_DIR}; fi

echo -e "\nZipping Output"
# Zip up framework, sources and LICENSE, ready to be uploaded to GitHub Releases and used by MatrixSDKCrypto.podspec
cp ${SRC_ROOT}/LICENSE $GENERATED_DIR
cd $GENERATED_DIR
zip -r MatrixSDKCryptoFFI.zip MatrixSDKCryptoFFI.xcframework Sources LICENSE
rm LICENSE

echo "XCFramework is ready 🚀"
