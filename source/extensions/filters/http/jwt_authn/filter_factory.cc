#include "extensions/filters/http/jwt_authn/filter_factory.h"

#include "envoy/config/filter/http/jwt_authn/v2alpha/config.pb.validate.h"
#include "envoy/registry/registry.h"

#include "extensions/filters/http/jwt_authn/config.h"
#include "extensions/filters/http/jwt_authn/filter.h"

using ::envoy::config::filter::http::jwt_authn::v2alpha::JwtAuthentication;

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace JwtAuthn {

Http::FilterFactoryCb
FilterFactory::createFilterFactoryFromProtoTyped(const JwtAuthentication& proto_config,
                                                 const std::string&,
                                                 Server::Configuration::FactoryContext& context) {
  auto config = std::make_shared<Config>(proto_config, context);
  return [config](Http::FilterChainFactoryCallbacks& callbacks) -> void {
    callbacks.addStreamDecoderFilter(std::make_shared<Filter>(config));
  };
}

/**
 * Static registration for this jwt_authn filter. @see RegisterFactory.
 */
static Registry::RegisterFactory<FilterFactory, Server::Configuration::NamedHttpFilterConfigFactory>
    register_;

} // namespace JwtAuthn
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
