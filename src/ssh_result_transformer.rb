require 'securerandom'
require 'json'

class SshResultTransformer
  def initialize(uuid_provider = SecureRandom)
    @uuid_provider = uuid_provider;
  end

  # expect(finding).toEqual({
  #                             id: '49bf7fd3-8512-4d73-a28f-608e493cd726',
  #                             name: 'SSH Compliance',
  #                             description: 'SSH Compliance Informations.',
  #                             category: 'SSH Service',
  #                             osi_layer: 'NETWORK',
  #                             severity: 'INFORMATIONAL',
  #                             reference: https://wiki.mozilla.org/Security/Guidelines/OpenSSH,
  #                             hint: null,
  #                             location: 'tcp://192.168.99.100:22',
  #                             attributes: {
  #                                 compliance_policy: 'Mozilla Modern',
  #                                 compliant: true,
  #                                 grade: 'B',
  #                                 scan_duration_seconds: '1235678',
  #                                 start_time: '234356',
  #                                 end_time: '2435678',
  #                             },
  #                         });
  # # expect(finding).toEqual({
  #   #                             id: '49bf7fd3-8512-4d73-a28f-608e493cd726',
  #   #                             name: 'Remove these Key Exchange Algos',
  #   #                             description: 'Remove these Key Exchange Algos: diffie-hellman-group14-sha1.',
  #   #                             category: 'SSH Service',
  #   #                             osi_layer: 'NETWORK',
  #   #                             severity: 'LOW',
  #   #                             reference: https://wiki.mozilla.org/Security/Guidelines/OpenSSH,
  #   #                             hint: null,
  #   #                             location: 'tcp://192.168.99.100:22',
  #   #                             attributes: {
  #   #
  #   #                             },
  #   #                         });


  def transform(results, timed_out: false)
    findings = results.map do |r|
      {
          id: @uuid_provider.uuid,
          name: r.dig('hostname'),
          description: 'lorem ipsum',
          category: 'SSH',
          osi_layer: 'APPLICATION',
          reference: {},
          severity: 'INFORMATIONAL',
          location: r.dig('ip'),
          hint: 'foobar',
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