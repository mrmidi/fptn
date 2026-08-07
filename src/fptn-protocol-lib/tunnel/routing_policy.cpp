/*=============================================================================
Copyright (c) 2026 Aleksandr Shabelnikov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/tunnel/routing_policy.h"

#include <cctype>
#include <string>
#include <string_view>
#include <vector>

namespace fptn::tunnel {

namespace {

constexpr std::string_view kDomainPrefix = "domain:";

std::string_view Trim(std::string_view value) noexcept {
  while (!value.empty() && (std::isspace(static_cast<unsigned char>(
                               value.front())) != 0)) {
    value.remove_prefix(1);
  }
  while (!value.empty() && (std::isspace(static_cast<unsigned char>(
                               value.back())) != 0)) {
    value.remove_suffix(1);
  }
  return value;
}

std::string ToLower(std::string_view value) {
  std::string out;
  out.reserve(value.size());
  for (const char c : value) {
    out.push_back(static_cast<char>(
        std::tolower(static_cast<unsigned char>(c))));
  }
  return out;
}

}  // namespace

std::string StaticDomainPolicy::NormalizeRule(std::string_view rule) {
  std::string_view trimmed = Trim(rule);
  if (trimmed.starts_with(kDomainPrefix)) {
    trimmed.remove_prefix(kDomainPrefix.size());
    trimmed = Trim(trimmed);
  }
  // A fully-qualified name may carry the root dot; the observed domains do not.
  while (!trimmed.empty() && trimmed.back() == '.') {
    trimmed.remove_suffix(1);
  }
  // A leading dot is a common way of writing "and all subdomains", which is
  // what every rule already means here.
  while (!trimmed.empty() && trimmed.front() == '.') {
    trimmed.remove_prefix(1);
  }
  if (trimmed.empty()) {
    return {};
  }
  // Reject anything that is not a plausible domain: an empty label (`a..b`)
  // would make the right-to-left walk unable to ever match it.
  if (trimmed.find("..") != std::string_view::npos) {
    return {};
  }
  return ToLower(trimmed);
}

void StaticDomainPolicy::AddRule(std::string_view rule, RouteAction action) {
  std::string normalized = NormalizeRule(rule);
  if (normalized.empty()) {
    return;
  }
  rules_[std::move(normalized)] = action;
}

void StaticDomainPolicy::AddRules(
    const std::vector<std::string>& rules, RouteAction action) {
  for (const auto& rule : rules) {
    AddRule(rule, action);
  }
}

RouteAction StaticDomainPolicy::Decide(
    const FlowMetadata&, std::string_view domain) const {
  if (domain.empty() || rules_.empty()) {
    return default_action_;
  }

  std::string candidate = ToLower(Trim(domain));
  while (!candidate.empty() && candidate.back() == '.') {
    candidate.pop_back();
  }
  if (candidate.empty()) {
    return default_action_;
  }

  // Walk labels right to left: `a.b.example.com` tries the whole name, then
  // `b.example.com`, `example.com`, `com`. Starting each step past a '.' is
  // what keeps the match label-aware -- `notmail.ru` only ever tries
  // `notmail.ru` and `ru`, never `mail.ru`.
  std::string_view suffix(candidate);
  for (;;) {
    const auto found = rules_.find(std::string(suffix));
    if (found != rules_.end()) {
      return found->second;
    }
    const auto dot = suffix.find('.');
    if (dot == std::string_view::npos) {
      break;
    }
    suffix.remove_prefix(dot + 1);
  }
  return default_action_;
}

}  // namespace fptn::tunnel
