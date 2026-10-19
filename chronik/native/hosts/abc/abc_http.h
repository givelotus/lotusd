// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_HOSTS_ABC_ABC_HTTP_H
#define CHRONIK_NATIVE_HOSTS_ABC_ABC_HTTP_H

#include <memory>

namespace chronik::native {
class Service;
} // namespace chronik::native

namespace chronik::native::abc {

/**
 * Serve /chronik and /chronik/ws on the node's Beast HTTP server in process
 * (SetChronikInProcessHandlers), replacing the loopback proxy to the Chronik
 * listener. Requests run on the Chronik query pool with the real client
 * address.
 */
void RegisterInProcessHttp(std::shared_ptr<Service> service);
/** Back to the proxy; closes open in-process WebSocket sessions. */
void UnregisterInProcessHttp();

} // namespace chronik::native::abc

#endif // CHRONIK_NATIVE_HOSTS_ABC_ABC_HTTP_H
