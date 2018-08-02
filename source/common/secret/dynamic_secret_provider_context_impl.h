#pragma once

#include <functional>

#include "envoy/init/init.h"
#include "envoy/secret/dynamic_secret_provider.h"

namespace Envoy {
namespace Secret {

class DynamicTlsCertificateSecretProviderContextImpl
    : public DynamicTlsCertificateSecretProviderContext {
public:
  DynamicTlsCertificateSecretProviderContextImpl(const LocalInfo::LocalInfo& local_info,
                                                 Event::Dispatcher& dispatcher,
                                                 Upstream::ClusterManager& cluster_manager,
                                                 Runtime::RandomGenerator& random,
                                                 Stats::Store& stats, Init::Manager& init_manager)
      : local_info_(local_info), dispatcher_(dispatcher), cluster_manager_(cluster_manager),
        random_(random), stats_(stats), init_manager_(init_manager),
        secret_manager_(cluster_manager.clusterManagerFactory().secretManager()) {}

  const LocalInfo::LocalInfo& localInfo() override { return local_info_; }

  Event::Dispatcher& dispatcher() override { return dispatcher_; }

  Upstream::ClusterManager& clusterManager() override { return cluster_manager_; }

  Runtime::RandomGenerator& random() override { return random_; }

  Stats::Store& stats() override { return stats_; }

  Init::Manager& initManager() override { return init_manager_; }

  Secret::SecretManager& secretManager() override { return secret_manager_; }

private:
  const LocalInfo::LocalInfo& local_info_;
  Event::Dispatcher& dispatcher_;
  Upstream::ClusterManager& cluster_manager_;
  Runtime::RandomGenerator& random_;
  Stats::Store& stats_;
  Init::Manager& init_manager_;
  Secret::SecretManager& secret_manager_;
};

} // namespace Secret
} // namespace Envoy