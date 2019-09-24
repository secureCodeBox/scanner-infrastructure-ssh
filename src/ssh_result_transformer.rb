require 'securerandom'
require 'json'

class SshResultTransformer
  def initialize(uuid_provider = SecureRandom)
    @uuid_provider = uuid_provider
  end

  def transform(results, timed_out: false)
    findings = []

    results.each do |r|
      location = r.dig('ip')
      hostname = (r.dig('hostname') unless r.dig('hostname').empty?)

      findings <<
        {
          id: @uuid_provider.uuid,
          name: 'SSH Compliance',
          description: 'SSH Compliance Information',
          category: 'SSH Service',
          osi_layer: 'NETWORK',
          severity: 'INFORMATIONAL',
          reference: {},
          hint: '',
          location: location,
          attributes: {
            hostname: hostname,
            server_banner:
              (r.dig('server_banner') unless r.dig('server_banner').empty?),
            ssh_version: r.dig('ssh_version'),
            os_cpe: r.dig('os_cpe'),
            ssh_lib_cpe: r.dig('ssh_lib_cpe'),
            compliance_policy: r.dig('compliance', 'policy'),
            compliant: r.dig('compliance', 'compliant'),
            grade: r.dig('compliance', 'grade'),
            start_time: r.dig('start_time'),
            end_time: r.dig('end_time'),
            scan_duration_seconds: r.dig('scan_duration_seconds'),
            references: r.dig('compliance', 'references'),
            auth_methods: r.dig('auth_methods'),
            key_algorithms: r.dig('key_algorithms'),
            encryption_algorithms:
              r.dig('encryption_algorithms_server_to_client'),
            mac_algorithms: r.dig('mac_algorithms_server_to_client'),
            compression_algorithms:
              r.dig('compression_algorithms_server_to_client')
          }
        }

      unless r.dig('compliance', 'recommendations').nil?
        r.dig('compliance', 'recommendations')
          .each do |policy_violation_message|
          findings <<
            create_policy_violation_finding(
              message: policy_violation_message,
              location: location,
              hostname: hostname
            )
        end
      end
    end

    findings
  end

  def get_policy_violation_type(message)
    type = message.split(': ')[0]

    case type
    when /^Add these key exchange algorithms/
      {
        name: 'Good / encouraged SSH key algorithms are missing',
        category: 'Missing SSH Key Algorithms'
      }
    when /^Add these MAC algorithms/
      {
        name: 'Good / encouraged SSH MAC algorithms are missing',
        category: 'Missing SSH MAC Algorithms'
      }
    when /^Add these encryption ciphers/
      {
        name: 'Good / encouraged SSH encryption ciphers are missing',
        category: 'Missing SSH encryption Ciphers'
      }
    when /^Add these compression algorithms/
      {
        name: 'Good / encouraged SSH compression algorithms are missing',
        category: 'Missing SSH compression algorithms'
      }
    when /^Add these authentication methods/
      {
        name: 'Good / encouraged SSH authentication methods are missing',
        category: 'Missing SSH authentication methods'
      }
    when /^Remove these key exchange algorithms/
      {
        name: 'Depracated / discouraged SSH key algorithms are used',
        category: 'Insecure SSH Key Algorithms'
      }
    when /^Remove these MAC algorithms/
      {
        name: 'Depracated / discouraged SSH MAC algorithms are used',
        category: 'Insecure SSH MAC Algorithms'
      }
    when /^Remove these encryption ciphers/
      {
        name: 'Depracated / discouraged SSH encryption ciphers are used',
        category: 'Insecure SSH encryption Ciphers'
      }
    when /^Remove these compression algorithms/
      {
        name: 'Depracated / discouraged SSH compression algorithms are used',
        category: 'Insecure SSH compression algorithms'
      }
    when /^Remove these authentication methods/
      {
        name: 'Discouraged SSH authentication methods are used',
        category: 'Discouraged SSH authentication methods'
      }
    when /^Update your ssh version to/
      {
        name: 'Outdated SSH protocol version used',
        category: 'Outdated SSH Protocol Version'
      }
    else
      raise Exception.new "Unexpected Policy Violation Type: '#{message}'"
    end
  end

  def create_policy_violation_finding(message:, location:, hostname:)
    policy_violation_type = get_policy_violation_type(message)

    payload = message.split(': ')[1].split(', ')

    {
      id: @uuid_provider.uuid,
      name: policy_violation_type[:name],
      description: '',
      category: policy_violation_type[:category],
      osi_layer: 'NETWORK',
      severity: 'MEDIUM',
      reference: {},
      hint: message,
      location: location,
      attributes: { hostname: hostname, payload: payload }
    }
  end
end
