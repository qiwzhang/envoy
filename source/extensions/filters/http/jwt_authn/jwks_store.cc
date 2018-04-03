#include "extensions/filters/http/jwt_authn/jwks_store.h"

#include "common/singleton/const_singleton.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace JwtAuthn {
namespace {
// Default cache expiration time in 5 minutes.
const int DefaultCacheDurationSec = 600;

// Struct to store const string values.
struct JwtConstValueStruct {
  // HTTP Protocol scheme prefix in JWT aud claim.
  const std::string HTTPSchemePrefix{"http://"};

  // HTTPS Protocol scheme prefix in JWT aud claim.
  const std::string HTTPSSchemePrefix{"https://"};
};
typedef ConstSingleton<JwtConstValueStruct> JwtConstValues;

// Searches protocol scheme prefix and trailing slash from aud, and
// returns aud without these prefix and suffix.
std::string sanitizeAudience(const std::string& aud) {
  bool sanitize_aud = false;
  int beg = 0;
  // Point beg to first character after protocol scheme prefix in audience.
  const auto& http_prefix = JwtConstValues::get().HTTPSchemePrefix;
  const auto& https_prefix = JwtConstValues::get().HTTPSSchemePrefix;
  if (aud.compare(0, http_prefix.length(), http_prefix) == 0) {
    beg = http_prefix.length();
    sanitize_aud = true;
  } else if (aud.compare(0, https_prefix.length(), https_prefix) == 0) {
    beg = https_prefix.length();
    sanitize_aud = true;
  }

  // Point end to trailing slash in aud.
  int end = aud.length() - 1;
  if (end >= 0 && aud[end] == '/') {
    --end;
    sanitize_aud = true;
  }

  if (sanitize_aud) {
    return aud.substr(beg, end - beg + 1);
  }
  return aud;
}

} // namespace

JwksStore::JwksStore(const ::envoy::config::filter::http::jwt_authn::v2alpha::JwtRule& jwt_rule)
    : jwt_rule_(jwt_rule) {
  for (const auto& aud : jwt_rule_.audiences()) {
    audiences_.insert(sanitizeAudience(aud));
  }
}

bool JwksStore::isExpired() const { return std::chrono::steady_clock::now() >= expiration_time_; }

// Check if an audience is allowed.
bool JwksStore::isAudienceAllowed(const std::vector<std::string>& jwt_audiences) {
  if (audiences_.empty()) {
    return true;
  }
  for (const auto& aud : jwt_audiences) {
    if (audiences_.find(sanitizeAudience(aud)) != audiences_.end()) {
      return true;
    }
  }
  return false;
}

// Set a pubkey as string.
Status JwksStore::setJwksText(const std::string& jwks_text) {
  auto tmp_jwks = Jwks::createFrom(jwks_text, Jwks::JWKS);
  if (tmp_jwks->getStatus() != Status::Ok) {
    return tmp_jwks->getStatus();
  }
  jwks_ = std::move(tmp_jwks);

  expiration_time_ = std::chrono::steady_clock::now();
  if (jwt_rule_.has_remote_jwks() && jwt_rule_.remote_jwks().has_cache_duration()) {
    const auto& duration = jwt_rule_.remote_jwks().cache_duration();
    expiration_time_ +=
        std::chrono::seconds(duration.seconds()) + std::chrono::nanoseconds(duration.nanos());
  } else {
    expiration_time_ += std::chrono::seconds(DefaultCacheDurationSec);
  }
  return Status::Ok;
}

JwksStoreMap::JwksStoreMap(
    const ::envoy::config::filter::http::jwt_authn::v2alpha::JwtAuthentication& config) {
  for (const auto& rule : config.rules()) {
    jwks_store_map_.emplace(rule.issuer(), rule);
  }
}

JwksStore* JwksStoreMap::findByIssuer(const std::string& issuer) {
  auto it = jwks_store_map_.find(issuer);
  if (it == jwks_store_map_.end()) {
    return nullptr;
  }
  return &it->second;
}

} // namespace JwtAuthn
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
