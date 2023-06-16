/**
 * @file fingerprint_c.h
 * @author Gautier Miquet
 * @brief Declaration of HTTP Fingerprinting method wrapper for C
 * @version 1.0.0
 * @date 2023-06-16
 */

#ifndef FINGER_FINGERPRINT_C_H
#define FINGER_FINGERPRINT_C_H

#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Computes a fingerprint from an HTTP Request
 *
 * @param uri Request URI
 * @param method Full HTTP method name (GET, POST, DELETE, ...)
 * @param version Full HTTP version (1.1, 1.0, ...)
 * @param headers Request headers
 * @param headers_count Number of headers in `headers`
 * @param payload Full string encoded payload
 *
 * @note This method allocates memory but does not clean it
 *  Do not forget to free the returned pointer to avoid memory
 *  leaks
 *
 * @return const char* The computed fingerprint
 */
const char* fingerprint_c(const char* uri, const char* method, const char* version, const char** headers, int headers_count, const char* payload);

#ifdef __cplusplus
}
#endif

#endif /* FINGER_FINGERPRINT_C_H */
