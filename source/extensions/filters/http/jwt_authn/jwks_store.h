#pragma once

#include <chrono>
#include <unordered_map>

#include "envoy/config/filter/http/jwt_authn/v2alpha/config.pb.h"

#include "extensions/filters/http/jwt_authn/jwks.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace JwtAuthn {

// Struct to hold a JwtRule config and its cached Jwks object.
class JwksStore {
public:
  JwksStore(const ::envoy::config::filter::http::jwt_authn::v2alpha::JwtRule& jwt_rule);

  // Return true if cached Jwks is expired.
  bool isExpired() const;

  // Get the JWT config.
  const ::envoy::config::filter::http::jwt_authn::v2alpha::JwtRule& jwt_rule() const {
    return jwt_rule_;
  }

  // Get the Jwks object.
  const Jwks* jwks() const { return jwks_.get(); }

  // Check if an audience is allowed.
  bool isAudienceAllowed(const std::vector<std::string>& jwt_audiences);

  // Set Jwks text string.
  Status setJwksText(const std::string& jwks_text);

private:
  // The issuer config
  const ::envoy::config::filter::http::jwt_authn::v2alpha::JwtRule& jwt_rule_;
  // Allowed audidences from config.
  std::set<std::string> audiences_;
  // The generated Jwks object.
  std::unique_ptr<Jwks> jwks_;
  // The Jwks expiration time.
  std::chrono::steady_clock::time_point expiration_time_;
};

// The object to hole a map of issuers to their JwksStore.
class JwksStoreMap {
public:
  // Load the config from envoy config.
  JwksStoreMap(const ::envoy::config::filter::http::jwt_authn::v2alpha::JwtAuthentication& config);

  // Lookup JwksStore by the issuer.
  JwksStore* findByIssuer(const std::string& issuer);

private:
  // The map of JwksStore objects indexed by their issuers.
  std::unordered_map<std::string, JwksStore> jwks_store_map_;
};

} // namespace JwtAuthn
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
