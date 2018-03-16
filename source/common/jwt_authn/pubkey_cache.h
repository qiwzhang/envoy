#pragma once

#include <chrono>
#include <unordered_map>

#include "common/jwt_authn/jwt.h"
#include "envoy/config/filter/http/jwt_authn/v2/config.pb.h"

namespace Envoy {
namespace JwtAuthn {
namespace {
// Default cache expiration time in 5 minutes.
const int kPubkeyCacheExpirationSec = 600;

// HTTP Protocol scheme prefix in JWT aud claim.
const std::string kHTTPSchemePrefix("http://");

// HTTPS Protocol scheme prefix in JWT aud claim.
const std::string kHTTPSSchemePrefix("https://");
}  // namespace

// Struct to hold an issuer cache item.
class PubkeyCacheItem {
 public:
 PubkeyCacheItem(const envoy::config::filter::http::jwtauthn::v2::JWT& jwt_config) : jwt_config_(jwt_config) {
    // Convert proto repeated fields to std::set.
    for (const auto& aud : jwt_config_.audiences()) {
      audiences_.insert(SanitizeAudience(aud));
    }
  }

  // Return true if cached pubkey is expired.
  bool Expired() const {
    return std::chrono::steady_clock::now() >= expiration_time_;
  }

  // Get the JWT config.
  const envoy::config::filter::http::jwtauthn::v2::JWT& jwt_config() const { return jwt_config_; }

  // Get the pubkey object.
  const Pubkeys* pubkey() const { return pubkey_.get(); }

  // Check if an audience is allowed.
  bool IsAudienceAllowed(const std::vector<std::string>& jwt_audiences) {
    if (audiences_.empty()) {
      return true;
    }
    for (const auto& aud : jwt_audiences) {
      if (audiences_.find(SanitizeAudience(aud)) != audiences_.end()) {
        return true;
      }
    }
    return false;
  }

  // Set a pubkey as string.
  Status SetKey(const std::string& pubkey_str) {
    auto pubkey = Pubkeys::CreateFrom(pubkey_str, Pubkeys::JWKS);
    if (pubkey->GetStatus() != Status::OK) {
      return pubkey->GetStatus();
    }
    pubkey_ = std::move(pubkey);

    expiration_time_ = std::chrono::steady_clock::now();
    if (jwt_config_.has_public_key_cache_duration()) {
      const auto& duration = jwt_config_.public_key_cache_duration();
      expiration_time_ += std::chrono::seconds(duration.seconds()) +
                          std::chrono::nanoseconds(duration.nanos());
    } else {
      expiration_time_ += std::chrono::seconds(kPubkeyCacheExpirationSec);
    }
    return Status::OK;
  }

 private:
  // Searches protocol scheme prefix and trailing slash from aud, and
  // returns aud without these prefix and suffix.
  std::string SanitizeAudience(const std::string& aud) {
    int beg = 0;
    int end = aud.length() - 1;
    bool sanitize_aud = false;
    // Point beg to first character after protocol scheme prefix in audience.
    if (aud.compare(0, kHTTPSchemePrefix.length(), kHTTPSchemePrefix) == 0) {
      beg = kHTTPSchemePrefix.length();
      sanitize_aud = true;
    } else if (aud.compare(0, kHTTPSSchemePrefix.length(),
                           kHTTPSSchemePrefix) == 0) {
      beg = kHTTPSSchemePrefix.length();
      sanitize_aud = true;
    }
    // Point end to trailing slash in aud.
    if (end >= 0 && aud[end] == '/') {
      --end;
      sanitize_aud = true;
    }
    if (sanitize_aud) {
      return aud.substr(beg, end - beg + 1);
    }
    return aud;
  }

  // The issuer config
  const envoy::config::filter::http::jwtauthn::v2::JWT& jwt_config_;
  // Use set for fast lookup
  std::set<std::string> audiences_;
  // The generated pubkey object.
  std::unique_ptr<Pubkeys> pubkey_;
  // The pubkey expiration time.
  std::chrono::steady_clock::time_point expiration_time_;
};

// Pubkey cache
class PubkeyCache {
 public:
  // Load the config from envoy config.
  PubkeyCache(const envoy::config::filter::http::jwtauthn::v2::JWTAuthentication& config) {
    for (const auto& jwt : config.jwts()) {
      pubkey_cache_map_.emplace(jwt.issuer(), jwt);
    }
  }

  // Lookup issuer cache map.
  PubkeyCacheItem* LookupByIssuer(const std::string& name) {
    auto it = pubkey_cache_map_.find(name);
    if (it == pubkey_cache_map_.end()) {
      return nullptr;
    }
    return &it->second;
  }

 private:
  // The public key cache map indexed by issuer.
  std::unordered_map<std::string, PubkeyCacheItem> pubkey_cache_map_;
};

}  // namespace JwtAuthn
}  // namespace Envoy
