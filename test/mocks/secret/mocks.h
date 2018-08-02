#pragma once

#include "envoy/secret/dynamic_secret_provider_factory.h"
#include "envoy/secret/secret_manager.h"
#include "envoy/ssl/tls_certificate_config.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace Secret {

class MockSecretManager : public SecretManager {
public:
  MockSecretManager();
  ~MockSecretManager();

  MOCK_METHOD1(addStaticSecret, void(const envoy::api::v2::auth::Secret& secret));
  MOCK_CONST_METHOD1(findStaticTlsCertificate, Ssl::TlsCertificateConfig*(const std::string& name));
  MOCK_METHOD2(findDynamicTlsCertificateSecretProvider,
               DynamicTlsCertificateSecretProviderSharedPtr(
                   const envoy::api::v2::core::ConfigSource& config_source,
                   const std::string& config_name));
  MOCK_METHOD3(setDynamicTlsCertificateSecretProvider,
               void(const envoy::api::v2::core::ConfigSource& config_source,
                    const std::string& config_name,
                    DynamicTlsCertificateSecretProviderSharedPtr provider));
};

class MockDynamicTlsCertificateSecretProvider : public DynamicTlsCertificateSecretProvider {
public:
  MockDynamicTlsCertificateSecretProvider();
  ~MockDynamicTlsCertificateSecretProvider();

  MOCK_CONST_METHOD0(secret, const Ssl::TlsCertificateConfig*());
  MOCK_METHOD1(addUpdateCallback, void(SecretCallbacks& callback));
  MOCK_METHOD1(removeUpdateCallback, void(SecretCallbacks& callback));
};

class MockDynamicTlsCertificateSecretProviderFactory
    : public DynamicTlsCertificateSecretProviderFactory {
public:
  MOCK_METHOD2(findOrCreate, DynamicTlsCertificateSecretProviderSharedPtr(
                                 const envoy::api::v2::core::ConfigSource& sds_config,
                                 std::string sds_config_name));
};

} // namespace Secret
} // namespace Envoy
