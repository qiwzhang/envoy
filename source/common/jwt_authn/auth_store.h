#pragma once

#include "common/common/logger.h"
#include "common/jwt_authn/pubkey_cache.h"
#include "common/jwt_authn/token_extractor.h"
#include "envoy/config/filter/http/jwt_authn/v2/config.pb.h"
#include "envoy/server/filter_config.h"
#include "envoy/thread_local/thread_local.h"

namespace Envoy {
namespace JwtAuthn {

// The JWT auth store object to store config and caches.
// It only has pubkey_cache for now. In the future it will have token cache.
// It is per-thread and stored in thread local.
class JwtAuthStore : public ThreadLocal::ThreadLocalObject {
 public:
  // Load the config from envoy config.
  JwtAuthStore(const envoy::config::filter::http::jwtauthn::v2::JWTAuthentication& config)
      : config_(config), pubkey_cache_(config_), token_extractor_(config_) {}

  // Get the Config.
  const envoy::config::filter::http::jwtauthn::v2::JWTAuthentication& config() const { return config_; }

  // Get the pubkey cache.
  PubkeyCache& pubkey_cache() { return pubkey_cache_; }

  // Get the private token extractor.
  const JwtTokenExtractor& token_extractor() const { return token_extractor_; }

 private:
  // Store the config.
  const envoy::config::filter::http::jwtauthn::v2::JWTAuthentication& config_;
  // The public key cache, indexed by issuer.
  PubkeyCache pubkey_cache_;
  // The object to extract token.
  JwtTokenExtractor token_extractor_;
};

// The factory to create per-thread auth store object.
class JwtAuthStoreFactory : public Logger::Loggable<Logger::Id::config> {
 public:
  JwtAuthStoreFactory(const envoy::config::filter::http::jwtauthn::v2::JWTAuthentication& config,
                      Server::Configuration::FactoryContext& context)
      : config_(config), tls_(context.threadLocal().allocateSlot()) {
    tls_->set(
        [this](Event::Dispatcher&) -> ThreadLocal::ThreadLocalObjectSharedPtr {
          return std::make_shared<JwtAuthStore>(config_);
        });
    ENVOY_LOG(info, "Loaded JwtAuthConfig: {}", config_.DebugString());
  }

  // Get per-thread auth store object.
  JwtAuthStore& store() { return tls_->getTyped<JwtAuthStore>(); }

 private:
  // The auth config.
  envoy::config::filter::http::jwtauthn::v2::JWTAuthentication config_;
  // Thread local slot to store per-thread auth store
  ThreadLocal::SlotPtr tls_;
};

}  // namespace JwtAuthn
}  // namespace Envoy
