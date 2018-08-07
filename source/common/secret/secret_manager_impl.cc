#include "common/secret/secret_manager_impl.h"

#include "envoy/common/exception.h"

#include "common/common/assert.h"
#include "common/secret/sds_api.h"
#include "common/ssl/tls_certificate_config_impl.h"

namespace Envoy {
namespace Secret {

void SecretManagerImpl::addStaticSecret(const envoy::api::v2::auth::Secret& secret) {
  switch (secret.type_case()) {
  case envoy::api::v2::auth::Secret::TypeCase::kTlsCertificate: {
    static_tls_certificate_secrets_[secret.name()] =
        std::make_unique<Ssl::TlsCertificateConfigImpl>(secret.tls_certificate());
    break;
  }
  default:
    throw EnvoyException("Secret type not implemented");
  }
}

const Ssl::TlsCertificateConfig*
SecretManagerImpl::findStaticTlsCertificate(const std::string& name) const {
  auto secret = static_tls_certificate_secrets_.find(name);
  return (secret != static_tls_certificate_secrets_.end()) ? secret->second.get() : nullptr;
}

void SecretManagerImpl::removeDeletedSecretProvider() {
  for (auto it = dynamic_secret_providers_.begin(); it != dynamic_secret_providers_.end();) {
    if (it->second.expired()) {
      it = dynamic_secret_providers_.erase(it);
    } else {
      ++it;
    }
  }
}

DynamicTlsCertificateSecretProviderSharedPtr SecretManagerImpl::findOrCreateDynamicSecretProvider(
    const envoy::api::v2::core::ConfigSource& sds_config_source, const std::string& config_name,
    Server::Configuration::TransportSocketFactoryContext& secret_provider_context) {
  std::string map_key = std::to_string(MessageUtil::hash(sds_config_source)) + config_name;

  auto secret_provider = dynamic_secret_providers_[map_key].lock();
  if (!secret_provider) {
    ASSERT(secret_provider_context.initManager() != nullptr);
    secret_provider = std::make_shared<SdsApi>(
        secret_provider_context.localInfo(), secret_provider_context.dispatcher(),
        secret_provider_context.random(), secret_provider_context.stats(),
        secret_provider_context.clusterManager(), *secret_provider_context.initManager(),
        sds_config_source, config_name);
    dynamic_secret_providers_[map_key] = secret_provider;
  }
  removeDeletedSecretProvider();

  return secret_provider;
}

} // namespace Secret
} // namespace Envoy
