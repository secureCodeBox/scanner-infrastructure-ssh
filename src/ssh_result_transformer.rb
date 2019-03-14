require 'securerandom'
require 'json'

class SshResultTransformer
  def initialize(uuid_provider = SecureRandom)
    @uuid_provider = uuid_provider;
  end

  def transform(results, timed_out: false)
    findings = results.map do |r|
      {
          id: @uuid_provider.uuid,
          name: r.dig('hostname'),
          description: '',
          category: 'SSH',
          osi_layer: 'APPLICATION',
          reference: {},
          severity: 'INFORMATIONAL',
          location: r.dig('ip'),
          hint: '',
          attributes: {}
      }
    end

    if timed_out
      findings.push({
       id: @uuid_provider.uuid,
       name: "SSH Scan timed out and could no be finished.",
       description: "SSH Scan didnt send any new requests for 5 minutes. This probably means that ssh_scan encountered some internal errors it could not handle.",
       osi_layer: 'NOT_APPLICABLE',
       severity: "MEDIUM",
       category: "ScanError",
       hint: "This could be related to a misconfiguration.",
       attributes: {}
       })
    end

    findings
  end
end