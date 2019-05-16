require 'securerandom'
require 'json'

class SshResultTransformer
  def initialize(uuid_provider = SecureRandom)
    @uuid_provider = uuid_provider;
  end


  def transform(results, timed_out: false)
    findings = []
    results.each do |r|
      findings << {
          id: @uuid_provider.uuid,
          name: 'SSH Compliance',
          description: 'SSH Compliance Information',
          category: 'SSH Service',
          osi_layer: 'NETWORK',
          severity: 'INFORMATIONAL',
          reference: {},
          hint: '',
          location: r.dig('ip'),
          attributes: {
              compliance_policy: r.dig('compliance', 'policy'),
              compliant: r.dig('compliance', 'compliant'),
              grade: r.dig('compliance', 'grade'),
              start_time: r.dig('start_time'),
              end_time: r.dig('end_time'),
              scan_duration_seconds: r.dig('scan_duration_seconds'),
              references: r.dig('compliance', 'references')
          }
      }

      unless r.dig('compliance', 'recommendations').nil?
        r.dig('compliance', 'recommendations').each do |f|
          findings << {
              id: @uuid_provider.uuid,
              name: f.split(':')[0],
              description: f.split(':')[1],
              category: 'SSH Service',
              osi_layer: 'NETWORK',
              severity: 'LOW',
              reference: {},
              hint: '',
              location: r.dig('ip'),
              attributes: {}
          }
        end
      end
    end

    findings
  end
end