#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2018 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_shared2'


module Whois
  class Parsers

    # Parser for the whois.nic.co server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNicCo < BaseShared2

      property_supported :expires_on do
        node("Registry Expiry Date") { |value| parse_time(value) }
      end

      property_supported :domain_id do
        node("Registry Domain ID")
      end

      property_supported :created_on do
        node("Creation Date") { |value| parse_time(value) }
      end

      property_supported :updated_on do
        node("Updated Date") { |value| parse_time(value) }
      end

      property_supported :registrar do
        return unless node("Registrar")
        Parser::Registrar.new({
            id:           node("Registrar IANA ID"),
            name:         node("Registrar"),
            organization: node("Registrar"),
            url:          node("Registrar URL"),
        })
      end

    end

  end
end
