#ifndef VC_VPN_API_H
#define VC_VPN_API_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * VPN Core API (Obfuscated)
 *
 * Features:
 * - JWT automatically generated from device fingerprint
 * - Endpoints encrypted in binary
 * - Responses automatically decrypted
 * - Returns JSON strings
 */

/**
 * Get list of VPN servers
 *
 * Returns JSON array:
 * [
 *   {
 *     "id": "1",
 *     "name": "US Server - New York",
 *     "country_code": "US",
 *     "protocols": ["OPENVPN", "IKEV2"]
 *   },
 *   ...
 * ]
 *
 * @return JSON string or NULL on error
 *         Caller must free with _Fr33_Str_()
 */
char* _L1sT_v3r_(void);

/**
 * Get server configuration by ID and protocol
 *
 * Returns JSON object (ServerConfiguration format):
 * {
 *   "id": "1",
 *   "name": "US Server",
 *   "protocol": "OPENVPN",
 *   "template": "...",
 *   "host": "...",
 *   "username": "...",
 *   "password": "..."
 * }
 *
 * @param server_id Server ID from list
 * @param protocol VPN protocol ("openvpn", "ikev2")
 * @return JSON string or NULL on error
 *         Caller must free with _Fr33_Str_()
 */
char* _G3t_C0nf_(const char* server_id, const char* protocol);

/**
 * Free string returned by API functions
 *
 * @param str String to free
 */
void _Fr33_Str_(char* str);

#ifdef __cplusplus
}
#endif

#endif // VC_VPN_API_H
