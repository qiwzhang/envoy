#include "common/protobuf/utility.h"

#include "extensions/filters/http/jwt_authn/jwks_store.h"

#include "test/test_common/utility.h"

#include <thread>

using ::envoy::config::filter::http::jwt_authn::v2alpha::JwtAuthentication;

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace JwtAuthn {
namespace {

const char AudienceTestConfig[] = R"(
rules:
  - issuer: issuer1
    audiences:
      - example_service0
      - http://example_service1
      - https://example_service2
      - example_service3/
      - http://example_service4/
      - https://example_service5/
)";

// Public key JwkEC
const std::string JwksText = R"(
    {
       "keys": [
          {
             "kty": "EC",
             "crv": "P-256",
             "x": "EB54wykhS7YJFD6RYJNnwbWEz3cI7CF5bCDTXlrwI5k",
             "y": "92bCBTvMFQ8lKbS2MbgjT3YfmYo6HnPEE2tsAqWUJw8",
             "alg": "ES256",
             "kid": "abc"
          },
          {
             "kty": "EC",
             "crv": "P-256",
             "x": "EB54wykhS7YJFD6RYJNnwbWEz3cI7CF5bCDTXlrwI5k",
             "y": "92bCBTvMFQ8lKbS2MbgjT3YfmYo6HnPEE2tsAqWUJw8",
             "alg": "ES256",
             "kid": "xyz"
          }
      ]
     }
)";

TEST(JwksStoreTest, TestAllowedAudiences) {
  JwtAuthentication config;
  MessageUtil::loadFromYaml(AudienceTestConfig, config);
  JwksStoreMap store_map(config);

  EXPECT_EQ(store_map.findByIssuer("wrong_issuer"), nullptr);
  auto jwks_store = store_map.findByIssuer("issuer1");
  EXPECT_NE(jwks_store, nullptr);

  for (const auto& aud : std::vector<std::string>{
           "example_service0",
           "example_service1",
           "example_service2",
           "example_service3",
           "example_service4",
           "example_service5",
       }) {
    EXPECT_TRUE(jwks_store->isAudienceAllowed({aud}));
    EXPECT_TRUE(jwks_store->isAudienceAllowed({aud + "/"}));
    EXPECT_TRUE(jwks_store->isAudienceAllowed({std::string("http://") + aud}));
    EXPECT_TRUE(jwks_store->isAudienceAllowed({std::string("https://") + aud}));
    EXPECT_TRUE(jwks_store->isAudienceAllowed({std::string("http://") + aud + "/"}));
    EXPECT_TRUE(jwks_store->isAudienceAllowed({std::string("https://") + aud + "/"}));
  }
}

TEST(JwksStoreTest, TestDefaultCacheDuration) {
  // With default cache duration
  JwtAuthentication config;
  auto rule = config.add_rules();
  rule->set_issuer("issuer1");

  JwksStoreMap store_map(config);

  auto jwks_store = store_map.findByIssuer("issuer1");
  EXPECT_EQ(jwks_store->setJwksText(JwksText), Status::Ok);
  EXPECT_TRUE(jwks_store->jwks());
  // Default is 5 minutes, it should not expired yet.
  EXPECT_FALSE(jwks_store->isExpired());
}

TEST(JwksStoreTest, TestShortCacheDuration) {
  // With default cache duration
  JwtAuthentication config;
  auto rule = config.add_rules();
  rule->set_issuer("issuer1");
  // Set 10 nanos cache duration
  rule->mutable_remote_jwks()->mutable_cache_duration()->set_nanos(10);

  JwksStoreMap store_map(config);

  auto jwks_store = store_map.findByIssuer("issuer1");
  EXPECT_EQ(jwks_store->setJwksText(JwksText), Status::Ok);
  EXPECT_TRUE(jwks_store->jwks());

  // sleep 20 nanoseconds
  std::this_thread::sleep_for(std::chrono::nanoseconds(20));
  // It should be expired now
  EXPECT_TRUE(jwks_store->isExpired());
}

} // namespace
} // namespace JwtAuthn
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
