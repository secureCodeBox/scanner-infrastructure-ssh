require 'securerandom'
require 'json'

class SshResultTransformer
  def initialize(uuid_provider = SecureRandom)
    @uuid_provider = uuid_provider;
  end

  def transform(result, timed_out: false)
    findings = result["Port: "].map do |port|
      {
          id: @uuid_provider.uuid,
          name: port.dig('name'),
          description: port.dig('description'),
          category: port.dig('check','name'),
          osi_layer: 'APPLICATION',
          reference: reference,
          severity: port.dig('severity').upcase,
          location: port.dig('request', 'url'),
          hint: port.dig('remedy_guidance') ? port.dig('remedy_guidance') : '',
          attributes: {
              ARACHNI_REQUEST: {
                 URL: port.dig('request', 'url'),
                 PARAMETER: port.dig('request', 'parameters'),
                 HEADERS: port.dig('request', 'headers'),
                 BODY: port.dig('request', 'body'),
                 METHOD: port.dig('request', 'method')
              },
              ARACHNI_RESPONSE: {
                 URL: port.dig('response', 'url'),
                 PARAMETER: port.dig('response', 'parameters'),
                 HEADERS: port.dig('response', 'headers'),
                 BODY: port.dig('response', 'body'),
                 STATUS: port.dig('response', 'code')
              }
          }
      }
    end

    if timed_out
      findings.push({
       id: @uuid_provider.uuid,
       name: "Arachni Scan timed out and could no be finished.",
       description: "Arachni Scan didnt send any new requests for 5 minutes. This probably means that arachni encountered some internal errors it could not handle.",
       osi_layer: 'NOT_APPLICABLE',
       severity: "MEDIUM",
       category: "ScanError",
       hint: "This could be related to a misconfiguration. But could also be related to internal instabilities of the arachni platform.",
       attributes: {}
       })
    end

    findings
  end
end