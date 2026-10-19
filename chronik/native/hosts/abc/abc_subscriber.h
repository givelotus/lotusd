// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_HOSTS_ABC_ABC_SUBSCRIBER_H
#define CHRONIK_NATIVE_HOSTS_ABC_ABC_SUBSCRIBER_H

#include <memory>

namespace node {
struct NodeContext;
} // namespace node

namespace chronik::native {
class Service;
} // namespace chronik::native

namespace chronik::native::abc {

class AbcHost;

/**
 * Register the validation-interface subscriber feeding `service`. Port of
 * chronik_validationinterface.cpp: events run on the dedicated worker thread
 * (BoundedTaskQueue, fail-closed on overflow).
 */
void StartSubscriber(const node::NodeContext &node, const AbcHost &host,
                     std::shared_ptr<Service> service);
/** Stop HTTP/WS request handlers (keeps indexing). */
void InterruptSubscriber();
/** Unregister, drain the worker, stop the service. */
void StopSubscriber();

} // namespace chronik::native::abc

#endif // CHRONIK_NATIVE_HOSTS_ABC_ABC_SUBSCRIBER_H
