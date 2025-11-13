#define MD4_DIGEST_LENGTH 16

/**
 * Compute MD4 hash of input data
 * @param out Output buffer - must be at least MD4_DIGEST_LENGTH (16) bytes
 * @param in Input data to hash
 * @param n Length of input data in bytes
 */
void mdfour(uint8_t *out, const uint8_t *in, int n);
