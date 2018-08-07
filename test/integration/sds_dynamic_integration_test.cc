#include <memory>
#include <string>

#include "envoy/service/discovery/v2/sds.pb.h"

#include "common/config/resources.h"
#include "common/event/dispatcher_impl.h"
#include "common/network/connection_impl.h"
#include "common/network/utility.h"
#include "common/ssl/context_config_impl.h"
#include "common/ssl/context_manager_impl.h"

#include "test/common/grpc/grpc_client_integration.h"
#include "test/integration/http_integration.h"
#include "test/integration/server.h"
#include "test/integration/ssl_utility.h"
#include "test/mocks/init/mocks.h"
#include "test/mocks/runtime/mocks.h"
#include "test/mocks/secret/mocks.h"
#include "test/test_common/network_utility.h"
#include "test/test_common/utility.h"

#include "absl/strings/match.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "integration.h"
#include "utility.h"

using testing::NiceMock;
using testing::Return;

namespace Envoy {
namespace Ssl {

// Hack to force linking of the service: https://github.com/google/protobuf/issues/4221.
const envoy::service::discovery::v2::SdsDummy _sds_dummy;

class SdsDynamicDownstreamIntegrationTest : public HttpIntegrationTest,
                                            public Grpc::GrpcClientIntegrationParamTest {
public:
  SdsDynamicDownstreamIntegrationTest()
      : HttpIntegrationTest(Http::CodecClient::Type::HTTP1, ipVersion()) {}

  void initialize() override {
    config_helper_.addConfigModifier([this](envoy::config::bootstrap::v2::Bootstrap& bootstrap) {
      auto* common_tls_context = bootstrap.mutable_static_resources()
                                     ->mutable_listeners(0)
                                     ->mutable_filter_chains(0)
                                     ->mutable_tls_context()
                                     ->mutable_common_tls_context();
      common_tls_context->add_alpn_protocols("http/1.1");

      auto* validation_context = common_tls_context->mutable_validation_context();
      validation_context->mutable_trusted_ca()->set_filename(
          TestEnvironment::runfilesPath("test/config/integration/certs/cacert.pem"));
      validation_context->add_verify_certificate_hash(
          "E0:F3:C8:CE:5E:2E:A3:05:F0:70:1F:F5:12:E3:6E:2E:"
          "97:92:82:84:A2:28:BC:F7:73:32:D3:39:30:A1:B6:FD");

      auto* secret_config = common_tls_context->add_tls_certificate_sds_secret_configs();
      secret_config->set_name("server_cert");
      auto* config_source = secret_config->mutable_sds_config();
      auto* api_config_source = config_source->mutable_api_config_source();
      api_config_source->set_api_type(envoy::api::v2::core::ApiConfigSource::GRPC);
      auto* grpc_service = api_config_source->add_grpc_services();
      setGrpcService(*grpc_service, "sds_cluster", fake_upstreams_.back()->localAddress());

      auto* sds_cluster = bootstrap.mutable_static_resources()->add_clusters();
      sds_cluster->MergeFrom(bootstrap.static_resources().clusters()[0]);
      sds_cluster->set_name("sds_cluster");
      sds_cluster->mutable_http2_protocol_options();
    });

    HttpIntegrationTest::initialize();
    client_ssl_ctx_ = createClientSslTransportSocketFactory(false, false, context_manager_);
  }

  void createUpstreams() override {
    HttpIntegrationTest::createUpstreams();
    fake_upstreams_.emplace_back(
        new FakeUpstream(0, FakeHttpConnection::Type::HTTP2, version_, enable_half_close_));
  }

  void TearDown() override {
    cleanUpSdsConnection();

    client_ssl_ctx_.reset();
    cleanupUpstreamAndDownstream();
    fake_upstream_connection_.reset();
    codec_client_.reset();
  }

  Network::ClientConnectionPtr makeSslClientConnection() {
    Network::Address::InstanceConstSharedPtr address = getSslAddress(version_, lookupPort("http"));
    return dispatcher_->createClientConnection(address, Network::Address::InstanceConstSharedPtr(),
                                               client_ssl_ctx_->createTransportSocket(), nullptr);
  }

  void createSdsStream(FakeUpstream& upstream) {
    sds_upstream_ = &upstream;
    AssertionResult result1 = sds_upstream_->waitForHttpConnection(*dispatcher_, sds_connection_);
    RELEASE_ASSERT(result1, result1.message());

    AssertionResult result2 = sds_connection_->waitForNewStream(*dispatcher_, sds_stream_);
    RELEASE_ASSERT(result2, result2.message());
    sds_stream_->startGrpcStream();
  }

  void sendSdsResponse() {
    envoy::api::v2::auth::Secret secret;
    secret.set_name("server_cert");
    auto* tls_certificate = secret.mutable_tls_certificate();
    tls_certificate->mutable_certificate_chain()->set_filename(
        TestEnvironment::runfilesPath("/test/config/integration/certs/servercert.pem"));
    tls_certificate->mutable_private_key()->set_filename(
        TestEnvironment::runfilesPath("/test/config/integration/certs/serverkey.pem"));

    envoy::api::v2::DiscoveryResponse discovery_response;
    discovery_response.set_version_info("1");
    discovery_response.set_type_url(Config::TypeUrl::get().Secret);
    discovery_response.add_resources()->PackFrom(secret);

    sds_stream_->sendGrpcMessage(discovery_response);
  }

  void cleanUpSdsConnection() {
    ASSERT(sds_upstream_ != nullptr);

    // Don't ASSERT fail if an ADS reconnect ends up unparented.
    sds_upstream_->set_allow_unexpected_disconnects(true);
    AssertionResult result = sds_connection_->close();
    RELEASE_ASSERT(result, result.message());
    result = sds_connection_->waitForDisconnect();
    RELEASE_ASSERT(result, result.message());
    sds_connection_.reset();
  }

  void testRouterHeaderOnlyRequestAndResponse(const std::string& response_code) {
    codec_client_ = makeHttpConnection(makeSslClientConnection());
    Http::TestHeaderMapImpl request_headers{{":method", "GET"},
                                            {":path", "/test/long/url"},
                                            {":scheme", "http"},
                                            {":authority", "host"},
                                            {"x-lyft-user-id", "123"}};
    auto response = sendRequestAndWaitForResponse(request_headers, 0, default_response_headers_, 0);

    EXPECT_TRUE(upstream_request_->complete());
    EXPECT_EQ(0U, upstream_request_->bodyLength());

    EXPECT_TRUE(response->complete());
    EXPECT_EQ(response_code, std::string(response->headers().Status()->value().c_str()));
    EXPECT_EQ(0U, response->body().size());
  }

  void makeSingleRequest(const std::string& response_code) {
    registerTestServerPorts({"http"});
    testRouterHeaderOnlyRequestAndResponse(response_code);
    cleanupUpstreamAndDownstream();
    fake_upstream_connection_ = nullptr;
  }

private:
  Runtime::MockLoader runtime_;
  Ssl::ContextManagerImpl context_manager_{runtime_};
  Secret::MockSecretManager secret_manager_;
  Network::TransportSocketFactoryPtr client_ssl_ctx_;
  FakeHttpConnectionPtr sds_connection_;
  FakeUpstream* sds_upstream_{};
  FakeStreamPtr sds_stream_;
};

INSTANTIATE_TEST_CASE_P(IpVersionsClientType, SdsDynamicDownstreamIntegrationTest,
                        GRPC_CLIENT_INTEGRATION_PARAMS);

TEST_P(SdsDynamicDownstreamIntegrationTest, Basic) {
  pre_worker_start_test_steps_ = [this]() {
    createSdsStream(*(fake_upstreams_[1]));
    sendSdsResponse();
  };
  initialize();

  makeSingleRequest("200");
}

#if 0
class SdsDynamicUpstreamIntegrationTest
    : public HttpIntegrationTest,
      public testing::TestWithParam<Network::Address::IpVersion> {
public:
  SdsDynamicUpstreamIntegrationTest()
      : HttpIntegrationTest(Http::CodecClient::Type::HTTP1, GetParam()) {}

  void initialize() override {
    config_helper_.addConfigModifier([](envoy::config::bootstrap::v2::Bootstrap& bootstrap) {
      bootstrap.mutable_static_resources()
          ->mutable_clusters(0)
          ->mutable_tls_context()
          ->mutable_common_tls_context()
          ->add_tls_certificate_sds_secret_configs()
          ->set_name("client_cert");

      auto* secret = bootstrap.mutable_static_resources()->add_secrets();
      secret->set_name("client_cert");
      auto* tls_certificate = secret->mutable_tls_certificate();
      tls_certificate->mutable_certificate_chain()->set_filename(
          TestEnvironment::runfilesPath("/test/config/integration/certs/clientcert.pem"));
      tls_certificate->mutable_private_key()->set_filename(
          TestEnvironment::runfilesPath("/test/config/integration/certs/clientkey.pem"));
    });

    HttpIntegrationTest::initialize();

    registerTestServerPorts({"http"});
  }

  void TearDown() override {
    cleanupUpstreamAndDownstream();
    fake_upstream_connection_.reset();
    codec_client_.reset();

    test_server_.reset();
    fake_upstreams_.clear();
  }

  void createUpstreams() override {
    fake_upstreams_.emplace_back(
        new FakeUpstream(createUpstreamSslContext(), 0, FakeHttpConnection::Type::HTTP1, version_));
  }

  Network::TransportSocketFactoryPtr createUpstreamSslContext() {
    envoy::api::v2::auth::DownstreamTlsContext tls_context;
    auto* common_tls_context = tls_context.mutable_common_tls_context();
    common_tls_context->add_alpn_protocols("h2");
    common_tls_context->add_alpn_protocols("http/1.1");
    common_tls_context->mutable_deprecated_v1()->set_alt_alpn_protocols("http/1.1");

    auto* validation_context = common_tls_context->mutable_validation_context();
    validation_context->mutable_trusted_ca()->set_filename(
        TestEnvironment::runfilesPath("test/config/integration/certs/cacert.pem"));
    validation_context->add_verify_certificate_hash(
        "E0:F3:C8:CE:5E:2E:A3:05:F0:70:1F:F5:12:E3:6E:2E:"
        "97:92:82:84:A2:28:BC:F7:73:32:D3:39:30:A1:B6:FD");

    auto* tls_certificate = common_tls_context->add_tls_certificates();
    tls_certificate->mutable_certificate_chain()->set_filename(
        TestEnvironment::runfilesPath("/test/config/integration/certs/servercert.pem"));
    tls_certificate->mutable_private_key()->set_filename(
        TestEnvironment::runfilesPath("/test/config/integration/certs/serverkey.pem"));

    Secret::MockDynamicTlsCertificateSecretProviderFactory provider_factory;
    auto cfg = std::make_unique<Ssl::ServerContextConfigImpl>(tls_context, secret_manager_,
                                                              provider_factory);

    static Stats::Scope* upstream_stats_store = new Stats::TestIsolatedStoreImpl();
    return std::make_unique<Ssl::ServerSslSocketFactory>(
        std::move(cfg), context_manager_, *upstream_stats_store, std::vector<std::string>{});
  }

private:
  Runtime::MockLoader runtime_;
  Ssl::ContextManagerImpl context_manager_{runtime_};
  Secret::MockSecretManager secret_manager_;
};

INSTANTIATE_TEST_CASE_P(IpVersions, SdsDynamicUpstreamIntegrationTest,
                        testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                        TestUtility::ipTestParamsToString);

TEST_P(SdsDynamicUpstreamIntegrationTest, RouterRequestAndResponseWithGiantBodyBuffer) {
  testRouterRequestAndResponseWithBody(16 * 1024 * 1024, 16 * 1024 * 1024, false, nullptr);
}
#endif

} // namespace Ssl
} // namespace Envoy
