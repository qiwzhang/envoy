#pragma once

#include "envoy/server/transport_socket_config.h"

#include "common/secret/dynamic_secret_provider_context_impl.h"

namespace Envoy {
namespace Server {
namespace Configuration {

/**
 * Implementation of TransportSocketFactoryContext.
 */
class TransportSocketFactoryContextImpl : public TransportSocketFactoryContext {
public:
  TransportSocketFactoryContextImpl(Ssl::ContextManager& context_manager, Stats::Scope& stats_scope,
                                    Upstream::ClusterManager& cm,
                                    const LocalInfo::LocalInfo& local_info,
                                    Event::Dispatcher& dispatcher,
                                    Envoy::Runtime::RandomGenerator& random, Stats::Store& stats)
      : context_manager_(context_manager), stats_scope_(stats_scope), cluster_manager_(cm),
        local_info_(local_info), dispatcher_(dispatcher), random_(random), stats_(stats) {}

  Ssl::ContextManager& sslContextManager() override { return context_manager_; }

  Stats::Scope& statsScope() const override { return stats_scope_; }

  Upstream::ClusterManager& clusterManager() override { return cluster_manager_; }

  const LocalInfo::LocalInfo& localInfo() override { return local_info_; }

  Event::Dispatcher& dispatcher() override { return dispatcher_; }

  Envoy::Runtime::RandomGenerator& random() override { return random_; }

  Stats::Store& stats() override { return stats_; }

  void createDynamicTlsCertificateSecretProviderContext(Init::Manager& init_manager) override {
    secret_provider_context_ =
        std::make_unique<Secret::DynamicTlsCertificateSecretProviderContextImpl>(
            local_info_, dispatcher_, cluster_manager_, random_, stats_, init_manager);
  }

  Secret::DynamicTlsCertificateSecretProviderContext&
  dynamicTlsCertificateSecretProviderContext() override {
    return *secret_provider_context_;
  }

private:
  Ssl::ContextManager& context_manager_;
  Stats::Scope& stats_scope_;
  Upstream::ClusterManager& cluster_manager_;
  const LocalInfo::LocalInfo& local_info_;
  Event::Dispatcher& dispatcher_;
  Envoy::Runtime::RandomGenerator& random_;
  Stats::Store& stats_;
  Secret::DynamicTlsCertificateSecretProviderContextPtr secret_provider_context_;
};

} // namespace Configuration
} // namespace Server
} // namespace Envoy
