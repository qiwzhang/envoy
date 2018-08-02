#pragma once

#include <string>

#include "envoy/event/dispatcher.h"
#include "envoy/init/init.h"
#include "envoy/local_info/local_info.h"
#include "envoy/runtime/runtime.h"
#include "envoy/secret/secret_callbacks.h"
#include "envoy/ssl/tls_certificate_config.h"
#include "envoy/stats/stats.h"
#include "envoy/upstream/cluster_manager.h"

namespace Envoy {
namespace Secret {

/**
 * An interface to fetch dynamic secret.
 *
 * TODO(JimmyCYJ): Support other types of secrets.
 */
class DynamicTlsCertificateSecretProvider {
public:
  virtual ~DynamicTlsCertificateSecretProvider() {}

  /**
   * @return the TlsCertificate secret. Returns nullptr if the secret is not found.
   */
  virtual const Ssl::TlsCertificateConfig* secret() const PURE;
  virtual void addUpdateCallback(SecretCallbacks& callback) PURE;
  virtual void removeUpdateCallback(SecretCallbacks& callback) PURE;
};

typedef std::shared_ptr<DynamicTlsCertificateSecretProvider>
    DynamicTlsCertificateSecretProviderSharedPtr;

/**
 * DynamicTlsCertificateSecretProviderFactoryContext passed to
 * DynamicTlsCertificateSecretProviderFactory to access resources which are needed for creating
 * dynamic tls certificate secret provider.
 */
class DynamicTlsCertificateSecretProviderContext {
public:
  virtual ~DynamicTlsCertificateSecretProviderContext() {}

  /**
   * @return information about the local environment the server is running in.
   */
  virtual const LocalInfo::LocalInfo& localInfo() PURE;

  /**
   * @return Event::Dispatcher& the main thread's dispatcher.
   */
  virtual Event::Dispatcher& dispatcher() PURE;

  /**
   * @return Upstream::ClusterManager.
   */
  virtual Upstream::ClusterManager& clusterManager() PURE;

  /**
   * @return RandomGenerator& the random generator for the server.
   */
  virtual Runtime::RandomGenerator& random() PURE;

  /**
   * @return the server-wide stats store.
   */
  virtual Stats::Store& stats() PURE;

  /**
   * @return the instance of init manager.
   */
  virtual Init::Manager& initManager() PURE;

  /**
   * @return the instance of secret manager.
   */
  virtual Secret::SecretManager& secretManager() PURE;
};

typedef std::unique_ptr<DynamicTlsCertificateSecretProviderContext>
    DynamicTlsCertificateSecretProviderContextPtr;

} // namespace Secret
} // namespace Envoy